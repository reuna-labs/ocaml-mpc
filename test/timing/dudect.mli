(** A dudect-style timing-leak detector.

    {1 What this does}

    For an operation under test, timings are collected for two classes of input
    — one fixed, one random — and Welch's t-test is applied to the two
    distributions. A large |t| means the running time depends on the input
    {e value}, which for a secret input is a timing side channel. The method is
    Reparaz, Balasch and Verbauwhede's {e dude, is my code constant time?}
    (2016).

    {1 What this cannot do}

    {b It can find leakage. It cannot prove its absence.} A clean result means
    this setup, on this machine, for these inputs, did not detect a difference.
    It is evidence, not a proof, and it is much weaker than a verified
    implementation or an instrumented run under valgrind.

    Three specific limits, stated because a harness whose limits are unstated
    gets read as stronger than it is:

    - Measurements are of a {e batch} of repetitions, because a single scalar
      multiplication is far below the resolution of any clock reachable from
      OCaml. That detects gross leakage — a data-dependent early exit, a
      variable-length loop — and not a single-cycle difference.
    - A general-purpose OS with frequency scaling, preemption and shared caches
      is a noisy instrument. Results vary between runs and between machines. A
      {e single} t-value crossing the threshold is therefore not evidence of
      anything: the first version of this harness reported |t| = 10.0 for
      [muladd] and 9.3 for [mul] in the same run, which cannot both be true of
      what is the same operation. {!run} takes the median over several
      independent rounds for that reason — noise averages out across rounds, a
      real difference does not.
    - The OCaml runtime allocates and may collect during a measurement.

    {1 Why the positive control is not optional}

    A detector that reports "no leakage" without having been shown to detect
    leakage at all is worthless: an instrument too blunt to see anything reports
    success on everything. So {!run} takes a known-variable-time operation
    alongside the ones under test, and if that control is {e not} flagged the
    whole run is reported as {!Inconclusive} rather than passing. *)

type verdict = {
  t : float;  (** |t| for the fixed input class against the random one *)
  floor : float;
      (** |t| for {e random against random} on the same operation. There is no
          true difference between two random classes, so this is the operation's
          noise floor for this machine and this run. *)
  leaked : bool;
      (** [t] exceeds both the absolute threshold and a multiple of [floor] *)
}

type outcome = {
  results : (string * verdict) list;
  control : string * verdict;
  inconclusive : bool;
      (** true when the positive control was not detected, meaning the harness
          was too blunt to conclude anything about the others *)
}

val threshold : float
(** 10.0, the value dudect uses. |t| above it is treated as evidence of leakage;
    the region between about 5 and 10 is genuinely ambiguous and is reported as
    not rejected, so a borderline number in the output is worth looking at even
    when the verdict is favourable. *)

val measure :
  ?repetitions:int ->
  ?samples:int ->
  fixed:string ->
  random:(unit -> string) ->
  (string -> unit) ->
  float
(** [measure ~fixed ~random f] returns |t| for [f] over the two input classes.

    Class assignment is interleaved rather than batched: measuring all of one
    class and then all of the other would attribute any thermal or scheduling
    drift to the class difference. *)

val run :
  ?repetitions:int ->
  ?samples:int ->
  ?rounds:int ->
  control:string * string * (unit -> string) * (string -> unit) ->
  (string * string * (unit -> string) * (string -> unit)) list ->
  outcome
(** Each entry is [(name, fixed_input, random_input, operation)]. [control] must
    be an operation known to be variable time. *)

val pp_outcome : Format.formatter -> outcome -> unit
