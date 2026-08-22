(** Two-round Pedersen distributed key generation, RFC 9591 Appendix D.

    This is what makes the library's premise true: no party, and no moment,
    holds the whole signing key. Each participant contributes a polynomial, and
    the group key is the sum of the contributions; a participant's signing share
    is the sum of the evaluations it receives.

    {1 Atomicity}

    Unlike signing — where the long-lived share is read-only and there is
    nothing to roll back — an aborted DKG {b must} leave nothing behind. A
    partial sum [s_i = sum over a subset of contributors] is a linear function
    of those contributors' secret polynomials, and partial sums from several
    aborted runs combine. So the protocol is atomic: either every honest party
    reaches the single terminal transition and emits its {!out}, or nobody keeps
    anything. There is no partial output and no resume.

    {1 Identifiable abort}

    The DKG has it, and uses it. Every proof of knowledge and every received
    share is checked against its sender's public commitment, so a failure names
    the party responsible rather than reporting that something, somewhere, went
    wrong.

    {1 Confidentiality of round 2}

    Round-2 messages carry secret shares. The core emits them marked private
    because it has no cryptographic channel of its own; supplying one is the
    transport's job, and {!Mpc_frost.Msg.encode} will not serialise a private
    payload without a seal.

    {1 Interoperability}

    RFC 9591 specifies this DKG in an appendix, publishes {b no test vectors}
    for it, and does not fix the proof-of-knowledge challenge hash. This
    implementation uses the ciphersuite's [hdkg] with the session identifier
    bound in — safe, and it prevents a round-1 message being replayed into
    another session — but it is therefore {b not} guaranteed to interoperate
    with another implementation's DKG. Signing is unaffected: that part is fully
    specified and fully vectored. See [CONTRIBUTING.md]. *)

module Make (C : Mpc.Group.CIPHERSUITE) : sig
  module V : module type of Mpc.Vss.Make (C)
  module M : module type of Msg.Make (C)

  type config = {
    self : Mpc.Session.peer;
    peers : Mpc.Session.peer list;  (** every participant, including [self] *)
    session : Mpc.Session.session_id;
    threshold : int;
    identifier : C.Scalar.t;
    id_of_peer : Mpc.Session.peer -> C.Scalar.t option;
  }

  type out = {
    identifier : C.Scalar.t;
    signing_share : C.Scalar.t;  (** {b secret} *)
    verification_share : C.Element.t;
    group_public_key : C.Element.t;
    commitment : V.t;  (** the combined commitment to the joint polynomial *)
    verification_shares : (C.Scalar.t * C.Element.t) list;
  }

  include
    Mpc.Session.MACHINE
      with type config := config
       and type msg = M.t
       and type out := out

  val secrets_cleared : t -> bool
  (** Whether this session still holds its polynomial. Exposed so tests can
      {e assert} that an aborted run kept nothing, rather than trust that it
      did. *)
end
