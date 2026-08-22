type verdict = { t : float; floor : float; leaked : bool }

type outcome = {
  results : (string * verdict) list;
  control : string * verdict;
  inconclusive : bool;
}

let threshold = 10.0
let floor_multiple = 3.0

(* Welch's t-test: unequal variances, which is the right choice here because the two
   classes may legitimately differ in spread as well as in mean. *)
let welch_t a b =
  let stats l =
    let n = float_of_int (Array.length l) in
    let mean = Array.fold_left ( +. ) 0. l /. n in
    let var =
      Array.fold_left (fun acc x -> acc +. ((x -. mean) ** 2.)) 0. l /. (n -. 1.)
    in
    (n, mean, var)
  in
  let na, ma, va = stats a and nb, mb, vb = stats b in
  if na < 2. || nb < 2. then 0.
  else
    let denom = sqrt ((va /. na) +. (vb /. nb)) in
    if denom = 0. then 0. else Float.abs ((ma -. mb) /. denom)

(* dudect crops the upper tail before testing: a preemption or a page fault produces an
   outlier orders of magnitude above the real cost, and a handful of those swamp the
   statistic in whichever class happened to catch them. *)
let crop_upper pct xs =
  let sorted = Array.copy xs in
  Array.sort compare sorted;
  let keep = int_of_float (float_of_int (Array.length sorted) *. pct) in
  Array.sub sorted 0 (max 2 keep)

let now_ns () = Mtime.Span.to_uint64_ns (Mtime_clock.elapsed ())

(* A self-contained xorshift, so class ordering is randomised without touching the
   global Random state and without the measurement depending on it. *)
let coin_state = ref 0x2545F4914F6CDD1DL

let coin () =
  let x = !coin_state in
  let x = Int64.logxor x (Int64.shift_left x 13) in
  let x = Int64.logxor x (Int64.shift_right_logical x 7) in
  let x = Int64.logxor x (Int64.shift_left x 17) in
  coin_state := x;
  Int64.logand x 1L = 1L

let measure ?(repetitions = 200) ?(samples = 2000) ~fixed ~random f =
  let ta = Array.make samples 0. and tb = Array.make samples 0. in
  (* Warm up: the first calls pay for lazy initialisation and cold caches, and would
     otherwise land entirely in whichever class went first. *)
  for _ = 1 to 100 do
    f fixed;
    f (random ())
  done;
  for i = 0 to samples - 1 do
    let r = random () in
    (* Randomise which class is timed first {e within} each sample, not just which
       sample comes next. Always measuring the fixed class first makes any order
       effect -- a cold branch predictor, a cache line fetched by the first loop and
       reused by the second -- look like a class difference, and it does not average
       out across rounds. It shows up worst on the cheapest operation, where a constant
       per-loop overhead is proportionally largest: before this, Eqaf.equal reported
       |t| = 18 while every arithmetic operation reported under 2. *)
    (* Copy the fixed input into a fresh string for each sample, rather than reusing
       one constant. Otherwise the two classes differ in more than their value: the
       constant is touched on every sample and stays in L1, while the random input is a
       fresh allocation that pays a cold miss once per sample. That asymmetry is a
       property of the harness, not of the operation, and it shows up worst on the
       cheapest operation, where one cache miss is a large fraction of the measurement
       window. It is why Eqaf.equal -- a purpose-built constant-time comparison --
       reported |t| = 10.5 against a noise floor of 1.2 while every arithmetic
       operation sat below 4. *)
    let f_copy = String.init (String.length fixed) (String.get fixed) in
    let fixed_first = coin () in
    let first, second = if fixed_first then (f_copy, r) else (r, f_copy) in
    let t0 = now_ns () in
    for _ = 1 to repetitions do
      f first
    done;
    let t1 = now_ns () in
    for _ = 1 to repetitions do
      f second
    done;
    let t2 = now_ns () in
    let d1 = Int64.to_float (Int64.sub t1 t0)
    and d2 = Int64.to_float (Int64.sub t2 t1) in
    if fixed_first then begin
      ta.(i) <- d1;
      tb.(i) <- d2
    end
    else begin
      ta.(i) <- d2;
      tb.(i) <- d1
    end
  done;
  welch_t (crop_upper 0.9 ta) (crop_upper 0.9 tb)

let median xs =
  let a = Array.of_list xs in
  Array.sort compare a;
  let n = Array.length a in
  if n = 0 then 0.
  else if n land 1 = 1 then a.(n / 2)
  else (a.((n / 2) - 1) +. a.(n / 2)) /. 2.

let run ?repetitions ?samples ?(rounds = 3) ~control cases =
  (* Two medians per operation.

     [t] is the real measurement: a fixed input class against a random one.

     [floor] is the same measurement with *both* classes random. Two random classes
     have no true difference between them, so whatever |t| that produces is this
     operation's noise floor -- on this machine, in this run, with this operation's
     own cost and allocation structure.

     The floor is not a refinement. Without it the harness reports whatever the machine
     happens to be doing: one run here put every arithmetic operation below |t| = 2 with
     the positive control at 70, and the next put them all near 11 with the control at
     872. The code had not changed. A fixed cut-off cannot tell those runs apart; a
     per-operation floor can. *)
  let measure_one (name, fixed, random, f) =
    let ts =
      List.init rounds (fun _ -> measure ?repetitions ?samples ~fixed ~random f)
    in
    let floors =
      List.init rounds (fun _ ->
          measure ?repetitions ?samples ~fixed:(random ()) ~random f)
    in
    let t = median ts and floor = median floors in
    (name, { t; floor; leaked = t > threshold && t > floor_multiple *. floor })
  in
  let control_result = measure_one control in
  let results = List.map measure_one cases in
  let inconclusive = not (snd control_result).leaked in
  { results; control = control_result; inconclusive }

let pp_verdict ppf v =
  Format.fprintf ppf "|t| = %7.2f  (noise floor %6.2f)  %s" v.t v.floor
    (if v.leaked then "LEAK DETECTED" else "not rejected")

let pp_outcome ppf o =
  let name, v = o.control in
  Format.fprintf ppf "@[<v>positive control (%s):@,  %-34s %a@," name ""
    pp_verdict v;
  List.iter
    (fun (n, v) -> Format.fprintf ppf "  %-34s %a@," n pp_verdict v)
    o.results;
  if o.inconclusive then
    Format.fprintf ppf
      "@,\
       INCONCLUSIVE: the positive control was not detected, so this run says@,\
      \  nothing about the operations above it -- the instrument was too blunt \
       to@,\
      \  see leakage that is known to be there.@,"
  else begin
    let leaks = List.filter (fun (_, v) -> v.leaked) o.results in
    if leaks = [] then
      Format.fprintf ppf
        "@,No leakage detected. This is evidence, not proof: see dudect.mli.@,"
    else
      Format.fprintf ppf "@,%d operation(s) show input-dependent timing.@,"
        (List.length leaks)
  end;
  Format.fprintf ppf "@]"
