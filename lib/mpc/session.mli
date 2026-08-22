(** A protocol session as a pure transition function.

    No clock, no scheduler, no I/O, no ambient randomness. Time enters only as a
    {!Timeout} input the driver chooses to inject; randomness enters only as a
    {!Rand.t} the caller supplies at [create]. That is what lets one
    implementation drive a Unix process, a MirageOS/Solo5 unikernel, and a fully
    deterministic in-memory simulator.

    {1 Abort, and what it does and does not destroy}

    In FROST signing there is nothing to roll back: the long-lived signing share
    is read-only for the entire protocol. Abort must therefore {b not} touch it
    — wiping the share on abort would turn a transient network fault into
    permanent key loss. What abort destroys is the ephemeral nonce, and it does
    so unconditionally and first, because a party that publishes a commitment,
    aborts, and later signs a different message with the same nonce leaks
    [lambda_i * s_i].

    The distributed key generation is the case that genuinely needs rollback.
    Aborting after round 2 would otherwise leave a partial sum
    [s_i = sum over a subset], which is a linear function of other parties'
    secret polynomials and combinable across aborted runs. The DKG is therefore
    atomic: either every honest party reaches the single terminal transition, or
    nobody keeps anything.

    {1 Replay}

    The session identifier is bound into every message header and checked before
    any cryptographic work, and into the DKG proof-of-knowledge challenge. It is
    deliberately {b not} bound into the FROST signing challenge: for
    FROST(Ed25519, SHA-512) that challenge must remain exactly the RFC 8032
    challenge, or the output stops being a verifiable Ed25519 signature. For
    signing, the real anti-replay guarantee is the nonce burn, not the
    identifier. *)

type peer = private int
(** A participant, in [[1, 65535]]. Maps onto a non-zero group scalar; zero is
    excluded because [f(0)] is the shared secret. *)

val peer : int -> (peer, [> `Invalid_range ]) result
val peer_to_int : peer -> int
val pp_peer : Format.formatter -> peer -> unit

type session_id = private string
(** Exactly 32 bytes. *)

val session_id : string -> (session_id, [> `Invalid_length ]) result

val derive_session_id :
  domain:string ->
  group_public_key:string ->
  participants:peer list ->
  context:string ->
  nonce:string ->
  session_id
(** Deterministic in its inputs plus a caller-supplied [nonce]. Two concurrent
    signings of the same message by different signer sets get different
    identifiers; a retry after an abort gets a different one because the caller
    must supply a fresh [nonce]. The caller is responsible for that freshness —
    a pure core cannot check it. *)

type abort_code =
  [ `Timeout
  | `Bad_message
  | `Bad_proof
  | `Bad_share
  | `Equivocation
  | `Cancelled
  | `Nonce_already_used
  | `Internal ]

type abort = {
  code : abort_code;
  culprits : peer list;  (** empty when the fault cannot be attributed *)
  round : int;
  detail : string;
}

val pp_abort : Format.formatter -> abort -> unit

type 'msg input =
  | Start
  | Recv of 'msg
  | Timeout of int  (** the driver asserts that this round has expired *)
  | Cancel

type ('msg, 'out) event =
  | Send of { to_ : [ `All | `Peer of peer ]; msg : 'msg; private_ : bool }
      (** [private_] means the payload must not travel in the clear; the
          transport is required to seal it. See {!Mpc_frost.Msg.encode}. *)
  | Output of 'out
  | Aborted of abort

(** {1 The slot table}

    Per-round, per-peer storage sized once at creation, so a hostile peer cannot
    make a session allocate. Messages are stored as raw encoded payloads and
    only decoded once accepted, which keeps a malformed message to a few
    comparisons rather than a scalar multiplication. *)

module Slots : sig
  type t
  (** Immutable. {!put} returns an updated table rather than mutating, so a
      state machine built on it can be a pure function of its state — which is
      what makes the nonce-burn argument in {!Mpc_frost.Sign} meaningful: the
      {e only} thing shared between an old state value and a new one is the
      deliberately mutable secret cell. *)

  val create : rounds:int -> peers:peer list -> t

  val put :
    t ->
    round:int ->
    from:peer ->
    string ->
    [ `Stored of t | `Duplicate | `Equivocation | `Unknown_peer | `Bad_round ]
  (** [`Duplicate] is a byte-identical resend and is not an error: networks
      retransmit. [`Equivocation] is a {e different} payload from the same peer
      for the same round, which breaks the protocol outright and must abort
      naming that peer. *)

  val get : t -> round:int -> from:peer -> string option
  val filled : t -> round:int -> (peer * string) list
  val missing : t -> round:int -> peer list
  val complete : t -> round:int -> bool
  val peers : t -> peer list

  val wipe : t -> t
  (** An emptied table. DKG round-2 payloads carry secret shares, so a
      terminating session drops them; as elsewhere, dropping a reference bounds
      a secret's lifetime but does not erase the bytes of an immutable string.
  *)
end

module type MACHINE = sig
  type t
  type config
  type msg
  type out

  val create : Rand.t -> config -> (t, Error.t) result
  val step : t -> msg input -> (t * (msg, out) event list, Error.t) result
  val round : t -> int

  val expected_from : t -> peer list
  (** Peers whose message for the current round has not arrived. The driver uses
      this to decide whom to nudge and when to give up; the core never decides.
  *)

  val status : t -> [ `Running | `Done | `Aborted of abort ]

  val wipe : t -> unit
  (** Idempotent. Erases every secret this session owns. Called automatically on
      abort and on completion; exposed so a driver can also call it on an
      unexpected shutdown path. *)
end
