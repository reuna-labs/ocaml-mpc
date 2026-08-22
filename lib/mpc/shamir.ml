module Make (C : Group.CIPHERSUITE) = struct
  module Sc = C.Scalar

  (* The coefficients live in one contiguous wipeable buffer rather than an array of
     scalars. A [Sc.t] is an immutable string that OCaml cannot overwrite, so an array
     of them can only be dropped, not erased. This buffer can be, and it holds the
     polynomial for the whole of a DKG round -- which is the durable secret here, and
     the one worth erasing.

     What this does not fix: [eval] and [coeff] deserialise through [Sc.t], so each
     read allocates a transient string that stays unerasable until collection. Closing
     that needs the group abstraction to expose [scalar_muladd_into]-style operations
     writing into caller-owned buffers, which the fork now provides but the GROUP
     signature does not yet surface. See CONTRIBUTING.md. *)
  type poly = { buf : Secret.t; len : int }
  type share = { id : Sc.t; value : Sc.t }

  let live what p =
    if Secret.wiped p.buf then
      invalid_arg
        (Printf.sprintf "Mpc.Shamir.%s: the polynomial has been wiped" what)

  let of_scalars a =
    let n = Array.length a in
    let b = Bytes.create (n * C.ns) in
    Array.iteri
      (fun i s -> Bytes.blit_string (Sc.serialize s) 0 b (i * C.ns) C.ns)
      a;
    { buf = Secret.of_bytes b; len = n }

  let of_coefficients a =
    if Array.length a < 1 then Error `Bad_threshold else Ok (of_scalars a)

  let degree p = p.len - 1

  let read p i =
    match
      Secret.with_bytes p.buf (fun b -> Bytes.sub_string b (i * C.ns) C.ns)
    with
    | None -> invalid_arg "Mpc.Shamir: the polynomial has been wiped"
    | Some raw -> (
        match Sc.deserialize raw with Ok s -> s | Error _ -> Sc.zero)

  let coeff p i =
    live "coeff" p;
    read p i

  let secret p =
    live "secret" p;
    read p 0

  let coefficients p =
    live "coefficients" p;
    Array.init p.len (read p)

  let random rand ~degree ~secret =
    if degree < 0 then Error `Bad_threshold
    else begin
      let a = Array.make (degree + 1) secret in
      let rec fill i =
        if i > degree then Ok (of_scalars a)
        else
          match Sc.random rand with
          | Error _ -> Error `Rng_failure
          | Ok s ->
              a.(i) <- s;
              fill (i + 1)
      in
      fill 1
    end

  (* Horner: f(x) = a_0 + x(a_1 + x(a_2 + ...)).

     The running value stays in a wipeable accumulator and is erased before returning,
     so the only unerasable copy of an intermediate is the one [Acc.reveal] produces at
     the end -- which is the share, and is about to be sent anyway. Evaluating with
     plain scalars instead would leave one unerasable copy per coefficient. *)
  let eval p x =
    live "eval" p;
    let acc = Sc.Acc.create () in
    let kx = Sc.Acc.of_scalar x in
    let term = Sc.Acc.create () in
    Sc.Acc.set acc (read p (p.len - 1));
    for i = p.len - 2 downto 0 do
      Sc.Acc.set term (read p i);
      Sc.Acc.muladd ~dst:acc ~a:acc ~b:kx ~c:term
    done;
    let out = Sc.Acc.reveal acc in
    Sc.Acc.wipe acc;
    Sc.Acc.wipe term;
    out

  let wipe p = Secret.wipe p.buf

  (* Identifiers must be distinct and non-zero: f(0) is the secret. *)
  let check_ids ids =
    let rec go seen = function
      | [] -> Ok ()
      | x :: tl ->
          if Sc.is_zero x then Error `Zero_id
          else if List.exists (Sc.equal x) seen then Error `Duplicate_id
          else go (x :: seen) tl
    in
    go [] ids

  let shares_of_poly p ~ids =
    match check_ids ids with
    | Error _ as e -> e
    | Ok () -> Ok (List.map (fun id -> { id; value = eval p id }) ids)

  let split rand ~secret ~threshold ~ids =
    let n = List.length ids in
    if threshold < 1 || threshold > n then Error `Bad_threshold
    else
      match check_ids ids with
      | Error e -> Error e
      | Ok () -> (
          match random rand ~degree:(threshold - 1) ~secret with
          | Error e -> Error e
          | Ok p -> (
              match shares_of_poly p ~ids with
              | Error e ->
                  wipe p;
                  Error e
              | Ok shares -> Ok (shares, p)))

  (* lambda_i = prod_{j != i} x_j / prod_{j != i} (x_j - x_i).
     Accumulate both products, then invert once. All inputs are public. *)
  let lagrange_num_den ~ids ~id =
    let rec go num den = function
      | [] -> Ok (num, den)
      | x :: tl ->
          if Sc.equal x id then go num den tl
          else go (Sc.mul num x) (Sc.mul den (Sc.sub x id)) tl
    in
    go Sc.one Sc.one ids

  let lagrange ~ids ~id =
    match check_ids ids with
    | Error e -> Error e
    | Ok () -> (
        if Sc.is_zero id then Error `Zero_id
        else if not (List.exists (Sc.equal id) ids) then
          Error `Not_a_participant
        else
          match lagrange_num_den ~ids ~id with
          | Error e -> Error e
          | Ok (num, den) -> (
              match Sc.invert den with
              | Error _ -> Error `Zero_scalar
              | Ok d -> Ok (Sc.mul num d)))

  let lagrange_all ~ids =
    match check_ids ids with
    | Error e -> Error e
    | Ok () -> (
        let pairs =
          List.map (fun id -> Result.get_ok (lagrange_num_den ~ids ~id)) ids
        in
        let dens = Array.of_list (List.map snd pairs) in
        match Sc.invert_batch dens with
        | Error _ -> Error `Zero_scalar
        | Ok inv -> Ok (List.mapi (fun i (num, _) -> Sc.mul num inv.(i)) pairs))

  let interpolate_secret shares =
    match shares with
    | [] -> Error `Bad_threshold
    | _ -> (
        let ids = List.map (fun s -> s.id) shares in
        match lagrange_all ~ids with
        | Error e -> Error e
        | Ok lambdas ->
            Ok
              (List.fold_left2
                 (fun acc l s -> Sc.muladd l s.value acc)
                 Sc.zero lambdas shares))

  let interpolate_element points =
    match points with
    | [] -> Error `Bad_threshold
    | _ -> (
        let ids = List.map fst points in
        match lagrange_all ~ids with
        | Error e -> Error e
        | Ok lambdas ->
            Ok
              (List.fold_left2
                 (* scalar_mul on a public Lagrange coefficient: allowlisted, see
                CONTRIBUTING.md. *)
                 (fun acc l (_, p) ->
                   C.Element.add acc (C.Element.scalar_mul l p))
                 C.Element.identity lambdas points))
end
