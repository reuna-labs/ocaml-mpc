(** Runs a sans-IO session over real flows.

    The protocol core has no clock and no sockets. This is where both live: the
    driver reads framed messages off each peer's flow, feeds them to
    {!Mpc.Session.MACHINE.step}, writes whatever the step emits, and injects a
    [Timeout] when a round has taken too long. That division is the whole point
    of the sans-IO design — the policy questions (how long to wait, whom to
    reconnect to, whether to retry) belong to the driver, and the core never
    decides them.

    Functorised over {!Mirage_flow.S}, so the same driver runs over TCP, over
    vsock, or over TLS in a unikernel. *)

module Make (Mach : Mpc.Session.MACHINE) (Flow : Mirage_flow.S) : sig
  type wire = {
    encode : Mach.msg -> (string, Mpc.Error.t) result;
    decode : string -> (Mach.msg, Mpc.Error.t) result;
  }
  (** Serialisation, supplied by the caller rather than assumed.

      This is also where the seal for private payloads is bound: build [encode]
      as [Mpc_frost.Msg.encode ~seal] and [decode] as
      [Mpc_frost.Msg.decode ~unseal]. A driver configured without one will fail
      — visibly, at the first DKG round-2 message — rather than putting a secret
      share on the wire in the clear. *)

  type error =
    [ `Aborted of Mpc.Session.abort
    | `Protocol of Mpc.Error.t
    | `Wire of string
    | `No_output ]
  (** [`No_output] means every flow closed, or the caller's timeout budget was
      never injected, and the session ended without reaching a decision. *)

  val pp_error : Format.formatter -> error -> unit

  val run :
    ?max_frame:int ->
    ?round_timeout_ns:int64 ->
    sleep_ns:(int64 -> unit Lwt.t) ->
    wire:wire ->
    peers:(Mpc.Session.peer * Flow.flow) list ->
    Mach.t ->
    (Mach.out, error) result Lwt.t
  (** [peers] maps every {e other} participant to an established flow; it must
      not contain this node, whose own messages the session already handles
      internally.

      [sleep_ns] is the clock, passed in rather than depended upon:
      [Lwt_unix.sleep] on Unix, [Mirage_sleep.ns] in a unikernel. Passing
      [fun _ -> fst (Lwt.wait ())] disables timeouts entirely, which is
      occasionally what a test wants and never what a deployment does.

      [round_timeout_ns] defaults to 30 seconds. A round that exceeds it aborts
      naming the peers whose messages are outstanding.

      The returned promise resolves when the session reaches a terminal state.
      Flows are not closed — the caller owns them — but the driver's reader
      threads are cancelled, so it leaks nothing.

      {b One session per flow.} A run owns each flow's byte stream for its whole
      lifetime, and the stream carries no session demultiplexing: frames are
      handed to this session and no other. Do not run two sessions over the same
      flow, whether concurrently or one after another. Two concurrent readers
      split the byte stream between them; sequentially, a peer that starts the
      next session early will have its first frames consumed by the previous
      session's reader before it is cancelled. Establish fresh flows per
      session, or put a demultiplexing layer above this one. A retry after an
      abort is a new session and therefore needs new flows too. *)
end
