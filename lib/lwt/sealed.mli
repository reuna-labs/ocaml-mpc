(** Confidentiality for the DKG's private payloads.

    {b Read this before using it.} FROST assumes an authenticated, confidential
    channel between participants, and the right way to get one is TLS or Noise
    {e on the flow}. If your transport is already confidential, you do not need
    this module: pass no [~seal] and let the channel do its job.

    This exists for transports that are not — a plain TCP socket on a trusted
    LAN, a vsock to a co-located enclave — where DKG round-2 messages would
    otherwise carry secret shares in the clear. An observer who collects [t] of
    those holds the key.

    {1 Construction}

    AEAD with a pre-shared symmetric key per {e ordered} peer pair. Each sealed
    payload carries a freshly drawn random nonce, so safety does not depend on
    session identifiers being unique — a caller error there would be
    catastrophic for a deterministic nonce and is merely wasteful here. The
    recipient's peer number is bound in as associated data, so a payload sealed
    for one participant cannot be replayed at another.

    {1 What it does not give you}

    Authentication of the {e sender}. A pairwise key proves the payload came
    from someone holding that key, which is the peer or you; it says nothing
    about the rest of the protocol, all of which travels unsealed. Message
    authenticity for the protocol as a whole is the transport's job. *)

module Make (A : Mirage_crypto.AEAD) : sig
  type t

  val v :
    self:Mpc.Session.peer ->
    rand:Mpc.Rand.t ->
    key_of_peer:(Mpc.Session.peer -> A.key option) ->
    t
  (** [key_of_peer p] is the AEAD key for the ordered pair (this node, [p]),
      derived once by the caller with {!Mirage_crypto.AEAD.of_secret} — for
      AES-256-GCM, from a 32-byte shared secret. Taking a derived key rather
      than a secret keeps the key schedule off the per-message path and out of
      this module's hands.

      [None] means there is no channel to that peer, and sealing for it fails.
  *)

  val nonce_size : int

  val overhead : int
  (** [nonce_size + A.tag_size]: how much longer a sealed payload is than its
      plaintext. Useful when sizing a frame budget. *)

  val seal : t -> peer:Mpc.Session.peer -> string -> string
  (** [peer] is the recipient.

      @raise Failure
        if no key is configured for [peer], or the randomness source misbehaves.
        Raised rather than returned because {!Mpc_frost.Msg.encode} takes a
        total sealing function; the driver turns the failure into a visible
        protocol error and sends nothing. *)

  val unseal :
    t -> peer:Mpc.Session.peer -> string -> (string, Mpc.Error.t) result
  (** [peer] is the {b sender} — the counterpart, mirroring {!seal}. This is
      what {!Mpc_frost.Msg.decode} passes. *)
end
