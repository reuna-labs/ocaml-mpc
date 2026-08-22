let src = Logs.Src.create "mpc.driver" ~doc:"ocaml-mpc session driver"

module Log = (val Logs.src_log src : Logs.LOG)

module Make (Mach : Mpc.Session.MACHINE) (Flow : Mirage_flow.S) = struct
  module Sess = Mpc.Session

  type wire = {
    encode : Mach.msg -> (string, Mpc.Error.t) result;
    decode : string -> (Mach.msg, Mpc.Error.t) result;
  }

  type error =
    [ `Aborted of Sess.abort
    | `Protocol of Mpc.Error.t
    | `Wire of string
    | `No_output ]

  let pp_error ppf = function
    | `Aborted a -> Sess.pp_abort ppf a
    | `Protocol e ->
        Format.fprintf ppf "protocol error: %s" (Mpc.Error.to_string e)
    | `Wire m -> Format.fprintf ppf "wire error: %s" m
    | `No_output ->
        Format.pp_print_string ppf "session ended without reaching a decision"

  let default_round_timeout_ns = 30_000_000_000L

  let run ?(max_frame = Framing.default_max_frame)
      ?(round_timeout_ns = default_round_timeout_ns) ~sleep_ns ~wire ~peers m0 =
    let open Lwt.Infix in
    let inbox, push = Lwt_stream.create () in
    let state = ref m0 in
    let outcome = ref None in
    let finished = ref false in
    let finish r =
      if not !finished then begin
        finished := true;
        outcome := Some r;
        (* Closing the stream is what unblocks the main loop and lets the reader and
           timer threads observe that they are done. *)
        push None
      end
    in
    (* Lwt is cooperative and there is no bind between the check and the push, so a
       reader cannot be preempted into pushing onto a closed stream. The guard is
       defence against that ceasing to be true if this is ever restructured: pushing
       after close raises, and a reader thread dying that way would be silent. *)
    let offer input =
      if not !finished then try push (Some input) with Lwt_stream.Closed -> ()
    in

    let send_to peer frame =
      match List.assoc_opt peer peers with
      | None ->
          (* Not an error: a session addresses its own messages to itself and handles
           them internally, so they never reach here. *)
          Lwt.return_unit
      | Some flow -> (
          Flow.write flow frame >|= function
          | Ok () -> ()
          | Error e ->
              (* A dead flow is not fatal on its own: the round timeout is what decides,
             and it names the peer. *)
              Log.warn (fun m ->
                  m "write to peer %d failed: %a" (Sess.peer_to_int peer)
                    Flow.pp_write_error e))
    in

    let dispatch evs =
      Lwt_list.iter_s
        (fun ev ->
          match ev with
          | Sess.Output o ->
              finish (Ok o);
              Lwt.return_unit
          | Sess.Aborted a ->
              finish (Error (`Aborted a));
              Lwt.return_unit
          | Sess.Send { to_; msg; private_ } -> (
              match wire.encode msg with
              | Error e ->
                  (* The common cause is a private payload with no seal configured. Failing
                 here is deliberate: the alternative is a secret share on the wire. *)
                  Log.err (fun m ->
                      m "refusing to send a%s message: %s"
                        (if private_ then " private" else "")
                        (Mpc.Error.to_string e));
                  finish (Error (`Protocol e));
                  Lwt.return_unit
              | Ok bytes ->
                  let frame = Framing.encode_string ~max_frame bytes in
                  let targets =
                    match to_ with
                    | `Peer p -> [ p ]
                    | `All -> List.map fst peers
                  in
                  Lwt_list.iter_s (fun p -> send_to p frame) targets))
        evs
    in

    let advance input =
      if !finished then Lwt.return_unit
      else
        match Mach.step !state input with
        | Error e ->
            finish (Error (`Protocol e));
            Lwt.return_unit
        | Ok (m, evs) ->
            state := m;
            dispatch evs
    in

    (* One reader per peer. A flow that closes or desynchronises simply stops
       delivering; the round timeout is what turns silence into a decision, and it is
       the driver's policy, not the core's. *)
    let reader (peer, flow) =
      let dec = Framing.create ~max_frame () in
      let rec drain () =
        match Framing.next dec with
        | `Need_more -> true
        | `Error m ->
            Log.warn (fun f -> f "peer %d: %s" (Sess.peer_to_int peer) m);
            false
        | `Message payload ->
            (match wire.decode (Cstruct.to_string payload) with
            | Ok msg -> offer (Sess.Recv msg)
            | Error e ->
                (* A malformed message is dropped, not fatal: admission checks in the core
               would reject it anyway, and one confused peer must not stall a round. *)
                Log.warn (fun f ->
                    f "peer %d sent an undecodable message: %s"
                      (Sess.peer_to_int peer) (Mpc.Error.to_string e)));
            drain ()
      in
      let rec loop () =
        if !finished then Lwt.return_unit
        else
          Flow.read flow >>= function
          | Error e ->
              Log.info (fun f ->
                  f "peer %d: read failed: %a" (Sess.peer_to_int peer)
                    Flow.pp_error e);
              Lwt.return_unit
          | Ok `Eof ->
              Log.info (fun f ->
                  f "peer %d closed the connection" (Sess.peer_to_int peer));
              Lwt.return_unit
          | Ok (`Data cs) ->
              Framing.feed dec cs;
              if drain () then loop () else Lwt.return_unit
      in
      Lwt.catch loop (function
        | Lwt.Canceled -> Lwt.return_unit
        | exn ->
            Log.warn (fun f ->
                f "peer %d: reader stopped: %s" (Sess.peer_to_int peer)
                  (Printexc.to_string exn));
            Lwt.return_unit)
    in

    (* The clock lives here and nowhere else. A round that has not advanced by the time
       the budget expires gets a Timeout injected; the core decides what that means. *)
    let rec timer_loop () =
      if !finished then Lwt.return_unit
      else
        let r = Mach.round !state in
        sleep_ns round_timeout_ns >>= fun () ->
        if !finished then Lwt.return_unit
        else begin
          if Mach.round !state = r then begin
            Log.info (fun f -> f "round %d timed out" r);
            offer (Sess.Timeout r)
          end;
          timer_loop ()
        end
    in
    let timer () =
      Lwt.catch timer_loop (function
        | Lwt.Canceled -> Lwt.return_unit
        | e -> Lwt.reraise e)
    in

    (* Reader threads are owned by this run and torn down when it ends. Leaving one
       parked in [Flow.read] would have it compete for bytes with whatever reads the
       flow next -- and since a stream carries no session framing, the two would split
       messages between them. Cancelling is not enough to make a flow safely reusable
       (see the note in the .mli); it is enough to stop this run from leaking threads. *)
    let readers = List.map (fun p -> reader p) peers in
    let timer_thread = timer () in
    let shutdown () =
      List.iter Lwt.cancel readers;
      Lwt.cancel timer_thread
    in
    advance Sess.Start >>= fun () ->
    Lwt_stream.iter_s advance inbox >|= fun () ->
    shutdown ();
    match !outcome with Some r -> r | None -> Error `No_output
end
