(** Two-round FROST signing as a pure state machine.

    {1 Why the nonce cannot be reused}

    Reusing a nonce pair across two different messages yields two equations in
    the same unknowns and recovers [lambda_i * s_i]. It is the one bug that
    makes a threshold signing library actively dangerous, so it is prevented
    structurally rather than by documentation:

    - No function in this module takes a nonce as an argument, and
      {!Mpc_frost.Core} is the only place one can be constructed. The nonce
      never leaves the session.
    - The nonce lives in a {!Mpc.Secret.t}, a {e mutable} cell, and is wiped
      before the signature share is returned. This matters because {!step} is a
      {e pure} function over an immutable state value: a caller can retain the
      state from before a step and call {!step} again with a different message.
      The retained value shares the same cell, so the replay finds it already
      erased and the session aborts with [`Nonce_already_used]. Immutability
      alone cannot give this.
    - There is no serialization function for {!t}, and a signing session must
      not survive a process restart. Persisting a live nonce is the same bug
      with a longer fuse; since a sans-IO core cannot stop a driver from writing
      state to disk, it instead declines to hand it the means.
    - A retry after an abort is a
      {e new session with a new identifier and fresh nonces}, never a resume.
      There is no [resume]. *)

module Make (C : Mpc.Group.CIPHERSUITE) : sig
  module F : module type of Core.Make (C)
  module M : module type of Msg.Make (C)

  type config = {
    self : Mpc.Session.peer;
    coordinator : Mpc.Session.peer;
    signers : Mpc.Session.peer list;
        (** the chosen [t]-subset, including [self] if signing *)
    session : Mpc.Session.session_id;
    identifier : C.Scalar.t;  (** [self]'s group identifier *)
    signing_share : C.Scalar.t option;
        (** [None] for a coordinator that does not sign *)
    group_public_key : C.Element.t;
    verification_shares : (C.Scalar.t * C.Element.t) list;
    id_of_peer : Mpc.Session.peer -> C.Scalar.t option;
    msg : string;
  }

  type out = string
  (** The aggregated signature, emitted by the coordinator only. *)

  include
    Mpc.Session.MACHINE
      with type config := config
       and type msg = M.t
       and type out := out

  val nonce_burned : t -> bool
  (** Exposed so tests can {e assert} the nonce was erased rather than trust
      that it was. That assertion is a shipped test. *)
end
