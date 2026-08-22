(** A deterministic in-memory network.

    Message ordering, duplication, loss and party crashes are all chosen by a
    seeded generator, so an entire n-party run — schedule included — replays
    exactly from its seed. A failing property test therefore reports a seed
    rather than an unreproducible anecdote.

    The simulator is generic over {!Mpc.Session.MACHINE} and never inspects a
    message: routing comes from the [Send] event alone. *)

type schedule =
  | Fifo  (** in-order delivery: the happy path *)
  | Reversed  (** deliver the newest pending message first *)
  | Shuffled of { window : int }
      (** pick pseudo-randomly among the oldest [window] pending messages, so
          ordering is adversarial but causally plausible *)

type fault =
  | Drop of { party : Mpc.Session.peer; round : int }
      (** discard messages {e sent by} [party] in [round] *)
  | Duplicate of { party : Mpc.Session.peer; round : int }
  | Crash of { party : Mpc.Session.peer; after_round : int }
      (** [party] stops stepping once it has entered a later round; its state is
          wiped, as an abruptly terminated node's would be *)

module Make (Mach : Mpc.Session.MACHINE) : sig
  type outcome = {
    steps : int;
    outputs : (Mpc.Session.peer * Mach.out) list;
    aborts : (Mpc.Session.peer * Mpc.Session.abort) list;
    delivered : int;
    dropped : int;
    crashed : Mpc.Session.peer list;
    exhausted : bool;
        (** the step budget ran out before the network went quiet *)
    final : (Mpc.Session.peer * Mach.t) list;
        (** each node's state when the run ended, so a test can assert on what a
            terminated session left behind rather than assume it *)
  }

  val run :
    seed:string ->
    ?schedule:schedule ->
    ?faults:fault list ->
    ?budget:int ->
    (Mpc.Session.peer * Mach.t) list ->
    outcome
  (** Starts every node, then delivers until the network is quiet or [budget]
      steps have been taken. [budget] defaults to 10000 and doubles as a
      liveness assertion: a protocol that fails to converge exhausts it rather
      than hanging. *)
end
