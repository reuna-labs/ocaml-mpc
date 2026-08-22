(** Unix sockets for ocaml-mpc.

    A {!Mirage_flow.S} over [Lwt_unix] sockets, plus address parsing and an
    accept loop. This is the only part of the library that touches [Unix];
    everything below it — the protocol core, the ciphersuite and the Lwt
    transport — is free of it and cross-compiles to a Solo5 unikernel unchanged.
*)

module Flow = Mirage_flow_unix.Fd
(** [Mirage_flow.S] over an [Lwt_unix] socket. Re-exported rather than
    reimplemented; the alias, rather than an ascription to [Mirage_flow.S], is
    deliberate — ascribing would make [write_error]'s private row opaque and the
    module would then no longer satisfy [Mirage_flow.S] at a functor
    application. *)

type address = Tcp of string * int | Unix_socket of string

val parse_address : string -> (address, [> `Msg of string ]) result
(** ["host:port"] or ["unix:/path/to/socket"]. *)

val pp_address : Format.formatter -> address -> unit
val connect : address -> (Flow.flow, [> `Msg of string ]) result Lwt.t

val listen :
  ?backlog:int ->
  address ->
  (Lwt_unix.file_descr, [> `Msg of string ]) result Lwt.t

val accept : Lwt_unix.file_descr -> Flow.flow Lwt.t

(** {1 Full-mesh connection establishment}

    Every FROST participant needs a flow to every other, which means agreeing
    who dials and who accepts and learning which peer is on the other end of an
    accepted socket. That is fiddly enough, and independent enough of the
    protocol, to belong here. *)

module Mesh : sig
  val connect :
    self:Mpc.Session.peer ->
    listen:address ->
    peers:(Mpc.Session.peer * address) list ->
    ?connect_timeout_s:float ->
    ?retry_delay_s:float ->
    unit ->
    ((Mpc.Session.peer * Flow.flow) list, [> `Msg of string ]) result Lwt.t
  (** Establishes exactly one flow to each entry of [peers], which must not
      contain [self].

      Who dials is settled by number: a node dials every peer numbered below it
      and accepts from every peer numbered above. Each pair is therefore
      connected once, with no negotiation and no duplicate-connection tie-break.
      Dials are retried until [connect_timeout_s] elapses, since the peer with
      the lower number may not be listening yet.

      A dialer announces itself with its two-byte peer number, which is how an
      acceptor learns who connected.

      {b That announcement is a claim, not proof.} Nothing here authenticates a
      peer. FROST assumes an authenticated, confidential channel; supply one by
      layering TLS with client certificates over these flows, or at minimum seal
      the private payloads with {!Mpc_lwt.Sealed}. Do not run this bare across a
      network you do not control. *)
end
