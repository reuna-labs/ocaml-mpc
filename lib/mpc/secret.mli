(** A wipeable secret.

    {b Why this is mutable, in a library whose state machines are pure.}
    [Session.step] is a pure function over an immutable state {e value}, so a
    caller may retain the state from before a step and call [step] again — with
    a {e different} message. For FROST signing that would produce a second
    signature share from the same nonce, and two such shares recover the signing
    share. Purity alone therefore cannot prevent nonce reuse.

    A {!t} is a mutable cell {e shared} between the old and the new state value.
    When the protocol burns a nonce it wipes the cell, and the replayed call —
    reached through the retained older state value — finds the same cell already
    erased. That is the property immutability cannot provide.

    {b What this does and does not protect.} {!wipe} genuinely overwrites the
    bytes it owns. It cannot reach transient immutable [string] copies that the
    runtime made (for instance the result of a C stub that allocates its
    output), nor copies the GC moved. Keep secret material inside a {!t} for its
    whole lifetime wherever the primitives allow it, and see the README for the
    limits of this guarantee. *)

type t

val of_string : string -> t
(** Copies [s] into a fresh wipeable buffer. The argument itself is not, and
    cannot be, erased; prefer {!of_bytes} where the caller owns the buffer. *)

val of_bytes : Bytes.t -> t
(** Takes ownership of [b]. The caller must not retain or reuse it. *)

val length : t -> int

val get : t -> string option
(** [None] once wiped. Returns a fresh immutable copy, which the caller is
    responsible for not retaining beyond its use. *)

val with_bytes : t -> (Bytes.t -> 'a) -> 'a option
(** [with_bytes t f] applies [f] to the live buffer without copying. [None] once
    wiped. [f] must not retain the buffer. *)

val wiped : t -> bool
(** Exposed so tests can {e assert} that erasure happened. That assertion is a
    shipped test, not a comment. *)

val wipe : t -> unit
(** Overwrite every byte with zero and mark the cell erased. Idempotent. *)

val wipe_all : t list -> unit

val equal : t -> t -> bool
(** Constant-time comparison of the contents. Two wiped secrets compare equal; a
    wiped and a live secret do not. *)
