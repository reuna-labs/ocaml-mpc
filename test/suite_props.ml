(** Randomised properties.

    The rest of the suite is example-based: fixed inputs, fixed schedules, known
    answers. That is the right shape for the RFC vectors and for the fault
    scenarios, where the point is to check a specific thing. It is the wrong
    shape for finding the input nobody thought of.

    Shrinking is why these are qcheck properties rather than seeded loops. When
    the codec fuzzer finds a byte string that makes [decode] raise, it reports
    the shortest such string, not the 4 KiB one it happened to generate. *)

open Testutil.Ed25519
module Sh = Mpc.Shamir.Make (Mpc_ed25519.Suite)
module V = Mpc.Vss.Make (Mpc_ed25519.Suite)
module M = Mpc_frost.Msg.Make (Mpc_ed25519.Suite)
module Sess = Mpc.Session
module D = Mpc_frost.Dealer.Make (Mpc_ed25519.Suite)
module Sg = Mpc_frost.Sign.Make (Mpc_ed25519.Suite)
module Net = Mpc_sim.Net.Make (Sg)

let test = QCheck_alcotest.to_alcotest

(* --- generators --- *)

let gen_bytes n =
  QCheck.Gen.(string_size ~gen:(map Char.chr (int_bound 255)) (return n))

let arb_scalar =
  QCheck.make
    ~print:(fun s -> hex (Sc.serialize s))
    QCheck.Gen.(
      map (fun w -> Result.get_ok (Sc.of_uniform_bytes w)) (gen_bytes 64))

let arb_element =
  QCheck.make
    ~print:(fun p -> hex (El.serialize p))
    QCheck.Gen.(
      map
        (fun w -> El.scalar_mul_base (Result.get_ok (Sc.of_uniform_bytes w)))
        (gen_bytes 64))

(* Small identifiers, shrunk toward 1, so a failure names the simplest party set. *)
let arb_id = QCheck.map_same_type (fun n -> 1 + (abs n mod 16)) QCheck.nat_small

(* --- scalar field --- *)

let p_ring =
  QCheck.Test.make ~count:300 ~name:"scalar field is a commutative ring"
    (QCheck.triple arb_scalar arb_scalar arb_scalar) (fun (a, b, c) ->
      Sc.equal (Sc.add a b) (Sc.add b a)
      && Sc.equal (Sc.mul a b) (Sc.mul b a)
      && Sc.equal (Sc.add (Sc.add a b) c) (Sc.add a (Sc.add b c))
      && Sc.equal (Sc.mul (Sc.mul a b) c) (Sc.mul a (Sc.mul b c))
      && Sc.equal (Sc.mul a (Sc.add b c)) (Sc.add (Sc.mul a b) (Sc.mul a c))
      && Sc.equal (Sc.add a (Sc.neg a)) Sc.zero
      && Sc.equal (Sc.sub a b) (Sc.add a (Sc.neg b)))

let p_muladd =
  QCheck.Test.make ~count:300 ~name:"muladd a b c = a*b + c"
    (QCheck.triple arb_scalar arb_scalar arb_scalar) (fun (a, b, c) ->
      Sc.equal (Sc.muladd a b c) (Sc.add (Sc.mul a b) c))

let p_invert =
  QCheck.Test.make ~count:150 ~name:"a * a^-1 = 1 for non-zero a" arb_scalar
    (fun a ->
      QCheck.assume (not (Sc.is_zero a));
      match Sc.invert a with
      | Ok ai -> Sc.equal (Sc.mul a ai) Sc.one
      | Error _ -> false)

let p_invert_batch =
  QCheck.Test.make ~count:100 ~name:"batch inversion agrees with single"
    (QCheck.list_size QCheck.Gen.(int_range 1 6) arb_scalar)
    (fun xs ->
      QCheck.assume (not (List.exists Sc.is_zero xs));
      let a = Array.of_list xs in
      match Sc.invert_batch a with
      | Error _ -> false
      | Ok inv ->
          (* Each batched inverse must equal the single-element one. *)
          Array.for_all2
            (fun i x ->
              match Sc.invert x with Ok e -> Sc.equal e i | Error _ -> false)
            inv a)

let p_scalar_codec =
  QCheck.Test.make ~count:300 ~name:"scalar serialization round-trips"
    arb_scalar (fun a ->
      Sc.equal a (Result.get_ok (Sc.deserialize (Sc.serialize a))))

(* --- group --- *)

let p_group_hom =
  QCheck.Test.make ~count:200 ~name:"(a+b)G = aG + bG and (ab)G = a(bG)"
    (QCheck.pair arb_scalar arb_scalar) (fun (a, b) ->
      El.equal
        (El.scalar_mul_base (Sc.add a b))
        (El.add (El.scalar_mul_base a) (El.scalar_mul_base b))
      && El.equal
           (El.scalar_mul_base (Sc.mul a b))
           (El.scalar_mul a (El.scalar_mul_base b)))

let p_group_laws =
  QCheck.Test.make ~count:200 ~name:"group laws"
    (QCheck.pair arb_element arb_element) (fun (p, q) ->
      El.equal (El.add p q) (El.add q p)
      && El.equal (El.add p El.identity) p
      && El.equal (El.sub p p) El.identity
      && El.equal (El.neg (El.neg p)) p)

let p_element_codec =
  QCheck.Test.make ~count:200 ~name:"element serialization round-trips"
    arb_element (fun p ->
      El.is_identity p
      || El.equal p (Result.get_ok (El.deserialize (El.serialize p))))

(* --- secret sharing --- *)

let p_share_reconstruct =
  QCheck.Test.make ~count:120
    ~name:"any t shares reconstruct, and VSS accepts them"
    (QCheck.triple arb_scalar QCheck.nat_small QCheck.nat_small)
    (fun (secret, t_raw, n_raw) ->
      let n = 1 + (abs n_raw mod 6) in
      let t = 1 + (abs t_raw mod n) in
      let r = rand_of_seed (hex (Sc.serialize secret)) in
      match Sh.split r ~secret ~threshold:t ~ids:(ids n) with
      | Error _ -> false
      | Ok (shares, poly) ->
          let c = V.commit poly in
          Sh.wipe poly;
          let every_share_verifies =
            List.for_all (fun s -> V.verify_share c s = Ok ()) shares
          in
          let subset = List.filteri (fun i _ -> i < t) shares in
          let reconstructs =
            match Sh.interpolate_secret subset with
            | Ok s -> Sc.equal s secret
            | Error _ -> false
          in
          every_share_verifies && reconstructs
          && El.equal (V.secret_commitment c) (El.scalar_mul_base secret))

let p_corrupt_share_rejected =
  QCheck.Test.make ~count:120 ~name:"any perturbation of a share is caught"
    (QCheck.pair arb_scalar arb_scalar) (fun (secret, delta) ->
      QCheck.assume (not (Sc.is_zero delta));
      let r = rand_of_seed (hex (Sc.serialize secret)) in
      match Sh.split r ~secret ~threshold:3 ~ids:(ids 5) with
      | Error _ -> false
      | Ok (shares, poly) ->
          let c = V.commit poly in
          Sh.wipe poly;
          List.for_all
            (fun (s : Sh.share) ->
              V.verify_share c { s with Sh.value = Sc.add s.Sh.value delta }
              = Error `Bad_share)
            shares)

(* --- codec --- *)

let arb_payload =
  let open QCheck.Gen in
  let el =
    map
      (fun w -> El.scalar_mul_base (Result.get_ok (Sc.of_uniform_bytes w)))
      (gen_bytes 64)
  in
  let sc =
    map (fun w -> Result.get_ok (Sc.of_uniform_bytes w)) (gen_bytes 64)
  in
  QCheck.make
    ~print:(fun p -> hex (M.encode_payload p))
    (oneof
       [
         map2 (fun h b -> M.Sign_commit { hiding = h; binding = b }) el el;
         map (fun z -> M.Sign_share { z }) sc;
         map3
           (fun i h b ->
             M.Sign_package { commitments = [ (i, (h, b)) ]; msg = "m" })
           sc el el;
         map3
           (fun c r mu ->
             M.Dkg_commit { commitment = [| c |]; pok_r = r; pok_mu = mu })
           el el sc;
       ])

let session = Result.get_ok (Sess.session_id (String.make 32 '\007'))
let peer n = Result.get_ok (Sess.peer n)

let p_msg_roundtrip =
  QCheck.Test.make ~count:300 ~name:"message round-trips through encode/decode"
    (QCheck.triple arb_payload arb_id arb_id) (fun (payload, a, b) ->
      QCheck.assume (a <> b);
      let m = M.make ~session ~round:1 ~src:(peer a) ~dst:(peer b) payload in
      match M.encode m with
      | Error _ -> false
      | Ok bytes -> (
          match M.decode bytes with
          | Error _ -> false
          | Ok m' ->
              String.equal (M.encode_payload payload)
                (M.encode_payload m'.M.payload)
              && m'.M.src = peer a
              && m'.M.dst = Some (peer b)))

let p_decode_never_raises =
  QCheck.Test.make ~count:2000 ~name:"decode never raises on arbitrary bytes"
    QCheck.string (fun s ->
      match M.decode s with _ -> true | exception _ -> false)

let p_truncation_rejected =
  QCheck.Test.make ~count:200
    ~name:"any truncation of a valid message is rejected"
    (QCheck.pair arb_payload QCheck.nat_small) (fun (payload, k) ->
      let m = M.make ~session ~round:0 ~src:(peer 1) ~dst:(peer 2) payload in
      match M.encode m with
      | Error _ -> true
      | Ok bytes ->
          let n = String.length bytes in
          let cut = abs k mod n in
          cut = 0 || Result.is_error (M.decode (String.sub bytes 0 cut)))

let p_corrupt_bytes_never_raise =
  QCheck.Test.make ~count:500 ~name:"corrupting a valid message never raises"
    (QCheck.triple arb_payload QCheck.nat_small QCheck.nat_small)
    (fun (payload, pos, delta) ->
      let m = M.make ~session ~round:0 ~src:(peer 1) ~dst:(peer 2) payload in
      match M.encode m with
      | Error _ -> true
      | Ok bytes -> (
          let n = String.length bytes in
          let i = abs pos mod n in
          let d = 1 + (abs delta mod 255) in
          let corrupted =
            String.mapi
              (fun j c ->
                if j = i then Char.chr ((Char.code c + d) land 0xff) else c)
              bytes
          in
          match M.decode corrupted with _ -> true | exception _ -> false))

(* --- the protocol itself --- *)

(* The property that matters most, and the one no example-based test can state: over
   arbitrary party counts, thresholds, signer subsets and message schedules, a run
   either produces a signature that verifies under the group public key or produces
   none at all. It must never produce one that does not verify -- that would be a
   silent failure a caller could ship. *)
let p_never_a_bad_signature =
  QCheck.Test.make ~count:60
    ~name:"a run yields a verifying signature or none, never a wrong one"
    (QCheck.quad QCheck.nat_small QCheck.nat_small QCheck.nat_small
       QCheck.nat_small) (fun (n_raw, t_raw, seed_raw, sched_raw) ->
      let n = 2 + (abs n_raw mod 5) in
      let t = 1 + (abs t_raw mod n) in
      let seed = Printf.sprintf "prop-%d-%d-%d" n t (abs seed_raw) in
      let r = rand_of_seed seed in
      let secret = Result.get_ok (Sc.random r) in
      match D.generate r ~secret ~threshold:t ~ids:(ids n) with
      | Error _ -> false
      | Ok (packages, pkp) ->
          (* An arbitrary t-subset of the n parties signs. *)
          let offset = abs seed_raw mod n in
          let signer_ixs =
            List.init t (fun i -> (i + offset) mod n) |> List.sort_uniq compare
          in
          if List.length signer_ixs <> t then true
          else
            let signers = List.map (fun i -> peer (i + 1)) signer_ixs in
            let coordinator = List.hd signers in
            let msg = "property" ^ seed in
            let sess =
              Sess.derive_session_id ~domain:"prop"
                ~group_public_key:(El.serialize pkp.D.pk) ~participants:signers
                ~context:msg ~nonce:(String.make 32 '\009')
            in
            let nodes =
              List.map
                (fun i ->
                  let kp = List.nth packages i in
                  ( peer (i + 1),
                    Result.get_ok
                      (Sg.create
                         (rand_of_seed (seed ^ string_of_int i))
                         {
                           Sg.self = peer (i + 1);
                           coordinator;
                           signers;
                           session = sess;
                           identifier = kp.D.id;
                           signing_share = Some kp.D.share;
                           group_public_key = pkp.D.pk;
                           verification_shares = pkp.D.verification_shares;
                           id_of_peer =
                             (fun p -> Some (id (Sess.peer_to_int p)));
                           msg;
                         }) ))
                signer_ixs
            in
            let schedule =
              match abs sched_raw mod 3 with
              | 0 -> Mpc_sim.Net.Fifo
              | 1 -> Mpc_sim.Net.Reversed
              | _ -> Mpc_sim.Net.Shuffled { window = 1 + (abs sched_raw mod 8) }
            in
            let out = Net.run ~seed ~schedule nodes in
            let ed_pub =
              Result.get_ok
                (Mirage_crypto_ec.Ed25519.pub_of_octets (El.serialize pkp.D.pk))
            in
            (* Any signature emitted must verify -- under our verifier and under a stock
             RFC 8032 one. Emitting none is acceptable; emitting a bad one is not. *)
            List.for_all
              (fun (_, sg) ->
                Mirage_crypto_ec.Ed25519.verify ~key:ed_pub sg ~msg)
              out.Net.outputs)

let suites =
  [
    ( "props-field",
      List.map test
        [ p_ring; p_muladd; p_invert; p_invert_batch; p_scalar_codec ] );
    ("props-group", List.map test [ p_group_hom; p_group_laws; p_element_codec ]);
    ( "props-sharing",
      List.map test [ p_share_reconstruct; p_corrupt_share_rejected ] );
    ( "props-codec",
      List.map test
        [
          p_msg_roundtrip;
          p_decode_never_raises;
          p_truncation_rejected;
          p_corrupt_bytes_never_raise;
        ] );
    ("props-protocol", List.map test [ p_never_a_bad_signature ]);
  ]
