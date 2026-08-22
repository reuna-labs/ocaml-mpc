(** The wire format.

    Distinct from {!Mpc_frost.Encoding}, which holds the RFC's {e normative}
    encodings — the ones that feed the hash functions and must never change.
    This format is ours. Conflating the two is the classic FROST
    interoperability bug, so they share no helpers and are tested separately.

    Every field is fixed width and big-endian, and every count is checked
    against the remaining input before anything is allocated. See {!Mpc.Codec}.
*)

module Make (C : Mpc.Group.CIPHERSUITE) : sig
  type payload =
    | Dkg_commit of {
        commitment : C.Element.t array;
        pok_r : C.Element.t;
        pok_mu : C.Scalar.t;
      }
    | Dkg_share of { value : C.Scalar.t }  (** {b private}: a secret share *)
    | Sign_commit of { hiding : C.Element.t; binding : C.Element.t }
    | Sign_package of {
        commitments : (C.Scalar.t * (C.Element.t * C.Element.t)) list;
        msg : string;
      }
    | Sign_share of { z : C.Scalar.t }
    | Sign_result of { signature : string }
        (** The aggregate, broadcast by the coordinator so that every signer
            learns it and can verify it for itself rather than take the
            coordinator's word. *)
    | Abort of Mpc.Session.abort

  type t = {
    version : int;
    suite : int;
    session : Mpc.Session.session_id;
    round : int;
    src : Mpc.Session.peer;
    dst : Mpc.Session.peer option;  (** [None] is a broadcast *)
    payload : payload;
  }

  val version : int

  val make :
    session:Mpc.Session.session_id ->
    round:int ->
    src:Mpc.Session.peer ->
    ?dst:Mpc.Session.peer ->
    payload ->
    t

  val is_private : payload -> bool
  (** True for payloads that must not travel in the clear. Currently only
      {!Dkg_share}: a DKG round-2 share is a secret, and a passive observer
      collecting [t] of them reconstructs the key. *)

  val encode_payload : payload -> string
  (** The payload alone, tagged with its kind byte, with no header and no
      sealing.

      A session stores this to detect equivocation — two {e different} payloads
      from one peer for one round — by exact comparison, and reads it back with
      {!decode_payload}. It is deliberately not a transport encoding: {!encode}
      is, and unlike this it refuses to emit a private payload in the clear.
      Comparing payloads rather than framed messages is what makes the check
      mean "the peer said two different things", not "two datagrams differed".
  *)

  val decode_payload : string -> (payload, Mpc.Error.t) result

  val encode :
    ?seal:(peer:Mpc.Session.peer -> string -> string) ->
    t ->
    (string, [> `Unsealed_private_payload ]) result
  (** A payload for which {!is_private} holds cannot be encoded without [seal].

      The protocol core produces DKG shares in the clear because it has no
      cryptographic channel; supplying the channel is the transport's job.
      Making [seal] mandatory turns "we forgot to encrypt the DKG shares" — a
      total key compromise — into an error at the call site rather than a
      sentence in a README that someone did not read. It is a structural
      reminder, not a substitute for the security considerations. *)

  val decode :
    ?unseal:(peer:Mpc.Session.peer -> string -> (string, Mpc.Error.t) result) ->
    string ->
    (t, Mpc.Error.t) result
  (** [peer] is the {e counterpart} — the other end of the channel this message
      travelled over. On {!encode} that is the destination; here it is the
      {b source}. Both ends must name the same pair, or they derive different
      keys and every private payload fails to open. *)

  val decode_header :
    string ->
    ( int
      * int
      * Mpc.Session.session_id
      * int
      * Mpc.Session.peer
      * Mpc.Session.peer option,
      Mpc.Error.t )
    result
  (** [(version, suite, session, round, src, dst)] without touching the payload,
      so a session can run its cheap admission checks — right session, known
      peer, plausible round — before spending a scalar multiplication on a
      message that a hostile peer may have made up. *)
end
