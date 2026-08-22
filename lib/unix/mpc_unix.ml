(* The flow is [Mirage_flow_unix.Fd], not a hand-rolled one. Socket I/O has more edge
   cases than it looks -- partial writes, ECONNRESET versus EPIPE, shutdown semantics --
   and there is no reason to reimplement a maintained version of them here. *)
module Flow = Mirage_flow_unix.Fd

type address = Tcp of string * int | Unix_socket of string

let parse_address s =
  if String.length s > 5 && String.sub s 0 5 = "unix:" then
    Ok (Unix_socket (String.sub s 5 (String.length s - 5)))
  else
    match String.rindex_opt s ':' with
    | None ->
        Error
          (`Msg (Printf.sprintf "address %S: expected host:port or unix:path" s))
    | Some i -> (
        let host = String.sub s 0 i in
        let port = String.sub s (i + 1) (String.length s - i - 1) in
        match int_of_string_opt port with
        | Some p when p > 0 && p < 65536 ->
            Ok (Tcp ((if host = "" then "0.0.0.0" else host), p))
        | _ ->
            Error (`Msg (Printf.sprintf "address %S: %S is not a port" s port)))

let pp_address ppf = function
  | Tcp (h, p) -> Format.fprintf ppf "%s:%d" h p
  | Unix_socket p -> Format.fprintf ppf "unix:%s" p

let sockaddr = function
  | Unix_socket p -> Lwt.return (Ok (Unix.ADDR_UNIX p, Unix.PF_UNIX))
  | Tcp (host, port) ->
      let open Lwt.Infix in
      Lwt.catch
        (fun () ->
          Lwt_unix.getaddrinfo host (string_of_int port)
            [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
          >|= function
          | { Unix.ai_addr; ai_family; _ } :: _ -> Ok (ai_addr, ai_family)
          | [] -> Error (`Msg (Printf.sprintf "cannot resolve %s:%d" host port)))
        (fun e -> Lwt.return (Error (`Msg (Printexc.to_string e))))

let connect addr =
  let open Lwt.Infix in
  sockaddr addr >>= function
  | Error _ as e -> Lwt.return e
  | Ok (sa, family) ->
      let fd = Lwt_unix.socket family Unix.SOCK_STREAM 0 in
      Lwt.catch
        (fun () ->
          (match addr with
          | Tcp _ -> Lwt_unix.setsockopt fd Unix.TCP_NODELAY true
          | Unix_socket _ -> ());
          Lwt_unix.connect fd sa >|= fun () -> Ok fd)
        (fun e ->
          Lwt_unix.close fd >|= fun () ->
          Error (`Msg (Printf.sprintf "connect: %s" (Printexc.to_string e))))

let listen ?(backlog = 16) addr =
  let open Lwt.Infix in
  sockaddr addr >>= function
  | Error _ as e -> Lwt.return e
  | Ok (sa, family) ->
      let fd = Lwt_unix.socket family Unix.SOCK_STREAM 0 in
      Lwt.catch
        (fun () ->
          Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
          Lwt_unix.bind fd sa >|= fun () ->
          Lwt_unix.listen fd backlog;
          Ok fd)
        (fun e ->
          Lwt_unix.close fd >|= fun () ->
          Error (`Msg (Printf.sprintf "listen: %s" (Printexc.to_string e))))

let accept fd =
  let open Lwt.Infix in
  Lwt_unix.accept fd >|= fun (c, _) ->
  (try Lwt_unix.setsockopt c Unix.TCP_NODELAY true with _ -> ());
  c

module Mesh = struct
  let id_bytes = 2

  let announce fd (peer : Mpc.Session.peer) =
    let n = Mpc.Session.peer_to_int peer in
    let b = Bytes.create id_bytes in
    Bytes.set b 0 (Char.chr ((n lsr 8) land 0xff));
    Bytes.set b 1 (Char.chr (n land 0xff));
    let open Lwt.Infix in
    Lwt_unix.write fd b 0 id_bytes >|= fun _ -> ()

  let read_announcement fd =
    let open Lwt.Infix in
    let b = Bytes.create id_bytes in
    let rec go off =
      if off >= id_bytes then Lwt.return (Some (Bytes.get_uint16_be b 0))
      else
        Lwt_unix.read fd b off (id_bytes - off) >>= function
        | 0 -> Lwt.return None
        | n -> go (off + n)
    in
    Lwt.catch (fun () -> go 0) (fun _ -> Lwt.return None)

  let dial_with_retry ~addr ~self ~deadline ~retry_delay_s =
    let open Lwt.Infix in
    let rec go () =
      connect addr >>= function
      | Ok fd -> announce fd self >|= fun () -> Ok fd
      | Error (`Msg m) ->
          (* The peer below us may simply not be listening yet; that is expected during
           start-up, not a failure, until the deadline says otherwise. *)
          if Unix.gettimeofday () > deadline then
            Lwt.return
              (Error
                 (`Msg
                    (Printf.sprintf "dialling %a: %s"
                       (fun () a -> Format.asprintf "%a" pp_address a)
                       addr m)))
          else Lwt_unix.sleep retry_delay_s >>= go
    in
    go ()

  let connect ~self ~listen:listen_addr ~peers ?(connect_timeout_s = 10.)
      ?(retry_delay_s = 0.05) () =
    let open Lwt.Infix in
    let self_n = Mpc.Session.peer_to_int self in
    if List.mem_assoc self peers then
      Lwt.return (Error (`Msg "Mesh.connect: peers must not contain self"))
    else begin
      let dial, accept_from =
        List.partition (fun (p, _) -> Mpc.Session.peer_to_int p < self_n) peers
      in
      let deadline = Unix.gettimeofday () +. connect_timeout_s in
      let close_server srv acc = Lwt_unix.close srv >|= fun () -> Ok acc in
      let acceptor =
        if accept_from = [] then Lwt.return (Ok [])
        else
          listen listen_addr >>= function
          | Error _ as e -> Lwt.return e
          | Ok srv ->
              let want = List.length accept_from in
              let rec loop acc =
                if List.length acc >= want then close_server srv acc
                else
                  accept srv >>= fun fd ->
                  read_announcement fd >>= function
                  | None -> Lwt_unix.close fd >>= fun () -> loop acc
                  | Some n -> (
                      match Mpc.Session.peer n with
                      | Ok p
                        when List.mem_assoc p accept_from
                             && not (List.mem_assoc p acc) ->
                          loop ((p, fd) :: acc)
                      | _ ->
                          (* An unexpected or duplicate peer number: drop the connection
                       rather than let it displace a legitimate one. *)
                          Lwt_unix.close fd >>= fun () -> loop acc)
              in
              Lwt.catch
                (fun () -> loop [])
                (fun e ->
                  Lwt_unix.close srv >|= fun () ->
                  Error
                    (`Msg
                       (Printf.sprintf "accepting: %s" (Printexc.to_string e))))
      in
      let dialer =
        Lwt_list.fold_left_s
          (fun acc (p, addr) ->
            match acc with
            | Error _ as e -> Lwt.return e
            | Ok l -> (
                dial_with_retry ~addr ~self ~deadline ~retry_delay_s
                >|= function
                | Ok fd -> Ok ((p, fd) :: l)
                | Error _ as e -> e))
          (Ok []) dial
      in
      Lwt.both acceptor dialer >|= fun (a, d) ->
      match (a, d) with
      | Ok a, Ok d -> Ok (a @ d)
      | Error e, _ | _, Error e -> Error e
    end
end
