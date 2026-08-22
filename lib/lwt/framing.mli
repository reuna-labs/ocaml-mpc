(** Length-prefixed framing for a byte stream.

    An incremental decoder: {!feed} it whatever a read produced, then {!next}
    until it says [`Need_more]. Frames are returned as views into the fed
    buffer, so the common case — a read that yields one or more whole frames —
    copies nothing.

    {b Bounded by construction.} A stream decoder is the one place where a peer
    chooses how much memory we allocate, so {!create} takes a maximum and a
    length prefix exceeding it is rejected {e before} any of the body is
    buffered. Without that, a peer claiming a 2 GiB frame would make a unikernel
    try to buffer 2 GiB.

    The incremental [feed]/[next]/[pending] shape follows [Cometbft.Framing] in
    the sibling ocaml-cometbft project (ISC, same author). The prefix here is a
    fixed 32-bit big-endian length rather than that one's LEB128 varint, for
    consistency with {!Mpc.Codec}: this library has no varints anywhere, so a
    frame header cannot be non-canonical. *)

val default_max_frame : int
(** 1 MiB. Comfortably above any FROST message — the largest is a signing
    package, which is a few hundred bytes plus the message being signed. *)

val header_length : int
(** 4. *)

val encode : ?max_frame:int -> Cstruct.t -> Cstruct.t
(** Prefix a payload with its length.
    @raise Invalid_argument
      if the payload exceeds [max_frame]. A payload we generated ourselves being
      too large is a bug here, not hostile input. *)

val encode_string : ?max_frame:int -> string -> Cstruct.t

type t

val create : ?max_frame:int -> unit -> t
val feed : t -> Cstruct.t -> unit

val next : t -> [ `Message of Cstruct.t | `Need_more | `Error of string ]
(** [`Error] is terminal: the stream is desynchronised or hostile and the caller
    must close the flow rather than try to resynchronise. *)

val pending : t -> int
(** Bytes buffered but not yet forming a complete frame. Never exceeds
    [header_length + max_frame]. *)
