(** Binary serialization for protocol messages.

    The shape — a writer that cannot fail, a reader that raises internally and
    is wrapped by a single {!R.run} entry point — follows {!Bitcoin.Codec} in
    the sibling ocaml-bitcoin project, which is already proven in this tree. Two
    deliberate departures:

    - {b All integers are big-endian and fixed width.} There is no little-endian
      primitive and no varint, because every field in this protocol has a length
      the ciphersuite fixes. What is absent cannot be misused, and the encoding
      is canonical by construction, which is a testable property rather than a
      hope.
    - {b Counts are checked against the remaining input before anything is
         allocated} ({!R.count16}). Each element occupies at least one byte, so
      a count larger than the bytes left cannot be honest. This is what stops a
      hostile length field from exhausting a unikernel's heap.

    Readers raise {!R.Parse_error} internally and {!R.run} is the only way to
    obtain one, so no exception escapes a public boundary. *)

type error =
  [ `Eof of int
  | `Trailing of int
  | `Invalid_length
  | `Invalid_format
  | `Msg of string ]

val pp_error : Format.formatter -> [< error ] -> unit

(** {1 Writing} *)

module W : sig
  type t

  val create : ?size:int -> unit -> t
  val contents : t -> string
  val length : t -> int
  val byte : t -> char -> unit

  val bytes : t -> string -> unit
  (** Raw, with no length prefix. *)

  val fixed : t -> len:int -> string -> unit
  (** Raw bytes of an exactly known length.
      @raise Invalid_argument
        if [String.length s <> len]. A writer cannot fail on well-typed input; a
        length mismatch here is a bug in the caller, not malformed input, so it
        is not a [result]. *)

  val u8 : t -> int -> unit
  val u16 : t -> int -> unit
  val u32 : t -> int32 -> unit

  val str16 : t -> string -> unit
  (** A [u16] length followed by the raw bytes. *)

  val str32 : t -> string -> unit
  (** A [u32] length followed by the raw bytes. For the signed message, which
      may be larger than 64 KiB. *)

  val vector16 : t -> (t -> 'a -> unit) -> 'a list -> unit
  (** A [u16] count followed by each element. *)

  val to_string : (t -> 'a -> unit) -> 'a -> string
end

(** {1 Reading} *)

module R : sig
  type t

  exception Parse_error of error
  (** Raised by the primitives below and caught by {!run}. Never let it escape a
      public API boundary. *)

  val fail : [< error ] -> 'a
  val run : ?exact:bool -> (t -> 'a) -> string -> ('a, error) result
  val pos : t -> int
  val remaining : t -> int
  val eof : t -> bool
  val byte : t -> char
  val take : t -> int -> string
  val u8 : t -> int
  val u16 : t -> int
  val u32 : t -> int32

  val fixed : t -> int -> string
  (** Alias for {!take}, named at call sites where the length is a ciphersuite
      constant. *)

  val str16 : t -> string
  val str32 : t -> string

  val count16 : t -> int
  (** A [u16] count, additionally rejected if it exceeds {!remaining}. Use this
      for every vector count. *)

  val vector16 : t -> (t -> 'a) -> 'a list
  val sub : t -> int -> t
end
