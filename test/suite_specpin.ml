(** The pinned specification is executable.

    `docs/dkls23-specification-pin.md` records the exact papers, parameters and
    deliberate departures for the threshold-ECDSA work. A document saying "every
    one of these belongs in a test that fails if the constant changes" is worth
    nothing unless such a test exists, so this is it: it reads the pin,
    re-derives the parameters from the analysis they came from, and fails if the
    two disagree.

    This is a direct response to what happened to CGGMP21 in November 2025,
    where the difference between a secure and an insecure implementation was
    which revision of a figure you read. It cannot stop someone implementing the
    wrong thing. It can stop a constant drifting away from the reasoning that
    produced it, silently. *)

let pin_file = "../docs/dkls23-specification-pin.md"

let pin =
  lazy
    (try
       let ic = open_in_bin pin_file in
       let n = in_channel_length ic in
       let s = really_input_string ic n in
       close_in ic;
       s
     with _ -> Alcotest.failf "cannot read %s" pin_file)

(* Pull "name  value" out of the fenced parameter summary. *)
let field name =
  let text = Lazy.force pin in
  let re = Str.regexp ("^" ^ Str.quote name ^ "[ \t]+\\([^ \t\n][^\n]*\\)$") in
  match Str.search_forward re text 0 with
  | _ -> String.trim (Str.matched_group 1 text)
  | exception Not_found -> Alcotest.failf "%s: no line for %S" pin_file name

let int_field name =
  let v = field name in
  match int_of_string_opt (List.hd (String.split_on_char ' ' v)) with
  | Some i -> i
  | None -> Alcotest.failf "%s: %S is not a number for %S" pin_file v name

let t_variant_ii_ot_count () =
  (* Asharov Variant II: m >= log q + 3s + 2*lambda_c, rounded up to a multiple of 8. *)
  let log_q = int_field "log q" in
  let lc = int_field "lambda_c" in
  let ls = int_field "lambda_s" in
  let m = int_field "m   (OTs per VOLE)" in
  let required = log_q + (3 * ls) + (2 * lc) in
  let rounded = (required + 7) / 8 * 8 in
  Alcotest.(check int)
    "m is the Variant II bound rounded to a multiple of 8" rounded m;
  Alcotest.(check bool) "m meets the bound" true (m >= required);
  (* The DKLs figure. If m ever equals this, someone has reverted to the unsound
     parameters that Asharov showed do not achieve the claimed security level. *)
  Alcotest.(check bool)
    "m is not the unsound DKLs bound" true
    (m > log_q + (2 * ls))

let t_rho_side_condition () =
  (* Asharov proves rho = 1 suffices provided log q >= lambda_c + 2*log2 m. DKLs prints
     rho = ceil(log q / lambda_c) = 2 for secp256k1, which they argue is a typo. *)
  let log_q = int_field "log q" in
  let lc = int_field "lambda_c" in
  let m = int_field "m   (OTs per VOLE)" in
  let rho = int_field "rho (masking)" in
  Alcotest.(check int) "rho is 1, not the printed 2" 1 rho;
  let bound = float_of_int lc +. (2. *. (log (float_of_int m) /. log 2.)) in
  Alcotest.(check bool)
    (Printf.sprintf "log q >= lambda_c + 2 log2 m  (%d >= %.1f)" log_q bound)
    true
    (float_of_int log_q >= bound)

let t_departures_are_still_recorded () =
  let text = Lazy.force pin in
  let contains needle =
    let n = String.length needle and l = String.length text in
    let rec go i = i + n <= l && (String.sub text i n = needle || go (i + 1)) in
    go 0
  in
  (* The OT flavour is a security decision, not an efficiency one: DKLs' Endemic-OT
     instantiation has a published attack that nullifies the consistency check. If the
     pin ever says Endemic, this test is the thing that makes someone re-read why. *)
  Alcotest.(check bool)
    "the pin still requires Sender-Random OT" true (contains "Sender-Random");
  Alcotest.(check bool)
    "the pin still warns against Endemic OT" true
    (contains "NOT Endemic OT");
  (* Both papers, with their revision dates, must stay named. *)
  List.iter
    (fun needle ->
      Alcotest.(check bool)
        (Printf.sprintf "the pin still names %S" needle)
        true (contains needle))
    [ "2023/765"; "2023-12-14"; "2026/976"; "2026-05-18" ]

let suites =
  [
    ( "spec-pin",
      [
        Alcotest.test_case "Variant II OT count" `Quick t_variant_ii_ot_count;
        Alcotest.test_case "rho side condition" `Quick t_rho_side_condition;
        Alcotest.test_case "departures still recorded" `Quick
          t_departures_are_still_recorded;
      ] );
  ]
