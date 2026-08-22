module Sess = Mpc.Session

type schedule = Fifo | Reversed | Shuffled of { window : int }

type fault =
  | Drop of { party : Mpc.Session.peer; round : int }
  | Duplicate of { party : Mpc.Session.peer; round : int }
  | Crash of { party : Mpc.Session.peer; after_round : int }

module Make (Mach : Mpc.Session.MACHINE) = struct
  module Sess = Mpc.Session

  type outcome = {
    steps : int;
    outputs : (Sess.peer * Mach.out) list;
    aborts : (Sess.peer * Sess.abort) list;
    delivered : int;
    dropped : int;
    crashed : Sess.peer list;
    exhausted : bool;
    final : (Sess.peer * Mach.t) list;
  }

  (* Faults are applied when a message is enqueued, so an in-flight entry needs only
     its destination: ordering comes from the list plus the schedule. *)
  type entry = { dst : Sess.peer; msg : Mach.msg }

  (* A counter-mode DRBG over SHA-256: deterministic, seeded, and independent of the
     library under test so a change there cannot silently reshuffle a schedule. *)
  type prng = { seed : string; mutable ctr : int }

  let prng seed = { seed; ctr = 0 }

  let next_int p bound =
    if bound <= 1 then 0
    else begin
      let d =
        Digestif.SHA256.(
          to_raw_string (digest_string (p.seed ^ "|" ^ string_of_int p.ctr)))
      in
      p.ctr <- p.ctr + 1;
      let v =
        Char.code d.[0]
        lor (Char.code d.[1] lsl 8)
        lor (Char.code d.[2] lsl 16)
        lor (Char.code d.[3] lsl 24)
      in
      v land 0x3fffffff mod bound
    end

  let run ~seed ?(schedule = Fifo) ?(faults = []) ?(budget = 10000) nodes =
    let p = prng seed in
    let state = Hashtbl.create 8 in
    List.iter (fun (peer, m) -> Hashtbl.replace state peer m) nodes;
    let peers = List.map fst nodes in
    let outputs = ref [] and aborts = ref [] in
    let crashed = ref [] and dropped = ref 0 and delivered = ref 0 in
    let pending = ref [] in

    let dead = Hashtbl.create 4 in
    let crash_round party =
      List.fold_left
        (fun acc f ->
          match f with
          | Crash { party = q; after_round } when q = party -> Some after_round
          | _ -> acc)
        None faults
    in
    let should_drop ~src ~round =
      List.exists
        (fun f ->
          match f with
          | Drop { party; round = r } -> party = src && r = round
          | _ -> false)
        faults
    in
    let should_dup ~src ~round =
      List.exists
        (fun f ->
          match f with
          | Duplicate { party; round = r } -> party = src && r = round
          | _ -> false)
        faults
    in

    let enqueue ~src ~round (ev : (Mach.msg, Mach.out) Sess.event) =
      match ev with
      | Sess.Output o -> outputs := (src, o) :: !outputs
      | Sess.Aborted a -> aborts := (src, a) :: !aborts
      | Sess.Send { to_; msg; private_ = _ } ->
          if should_drop ~src ~round then incr dropped
          else begin
            let dsts =
              match to_ with
              | `Peer p -> [ p ]
              | `All -> List.filter (fun q -> q <> src) peers
            in
            let copies = if should_dup ~src ~round then 2 else 1 in
            for _ = 1 to copies do
              List.iter (fun dst -> pending := !pending @ [ { dst; msg } ]) dsts
            done
          end
    in

    (* A crashed party emits the messages of its final round and only then dies: that
       is the case that matters -- a node that has already published a commitment and
       then drops off, leaving its peers waiting. Killing it before it speaks would be
       indistinguishable from never having started. *)
    let record peer (m, evs) =
      Hashtbl.replace state peer m;
      let r = Mach.round m in
      List.iter (fun ev -> enqueue ~src:peer ~round:r ev) evs;
      match crash_round peer with
      | Some after when r >= after && not (Hashtbl.mem dead peer) ->
          Hashtbl.replace dead peer ();
          crashed := peer :: !crashed;
          Mach.wipe m
      | _ -> ()
    in

    let alive peer = not (Hashtbl.mem dead peer) in

    (* Start every node. *)
    List.iter
      (fun peer ->
        let m = Hashtbl.find state peer in
        match Mach.step m Sess.Start with
        | Ok r -> record peer r
        | Error _ -> ())
      peers;

    let pick () =
      let n = List.length !pending in
      if n = 0 then None
      else
        let i =
          match schedule with
          | Fifo -> 0
          | Reversed -> n - 1
          | Shuffled { window } -> next_int p (min window n)
        in
        let e = List.nth !pending i in
        pending := List.filteri (fun j _ -> j <> i) !pending;
        Some e
    in

    let steps = ref 0 in
    let exhausted = ref false in
    let rec loop () =
      if !steps >= budget then exhausted := true
      else
        match pick () with
        | None -> ()
        | Some e ->
            incr steps;
            if not (alive e.dst) then incr dropped
            else begin
              incr delivered;
              let m = Hashtbl.find state e.dst in
              match Mach.step m (Sess.Recv e.msg) with
              | Ok r -> record e.dst r
              | Error _ -> ()
            end;
            loop ()
    in
    loop ();
    {
      steps = !steps;
      outputs = List.rev !outputs;
      aborts = List.rev !aborts;
      delivered = !delivered;
      dropped = !dropped;
      crashed = !crashed;
      exhausted = !exhausted;
      final = List.map (fun p -> (p, Hashtbl.find state p)) peers;
    }
end
