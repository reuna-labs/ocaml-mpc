type peer = int

let peer n = if n < 1 || n > 0xffff then Error `Invalid_range else Ok n
let peer_to_int p = p
let pp_peer ppf p = Format.fprintf ppf "peer:%d" p

type session_id = string

let session_id s = if String.length s <> 32 then Error `Invalid_length else Ok s

let derive_session_id ~domain ~group_public_key ~participants ~context ~nonce =
  let b = Buffer.create 128 in
  let tagged tag s =
    Buffer.add_string b tag;
    Buffer.add_char b '\000';
    (* Length-prefix every field: without it, ("ab", "c") and ("a", "bc") would hash
       identically and two distinct sessions could share an identifier. *)
    Buffer.add_string b (string_of_int (String.length s));
    Buffer.add_char b ':';
    Buffer.add_string b s
  in
  tagged "domain" domain;
  tagged "pk" group_public_key;
  tagged "parties"
    (String.concat ","
       (List.map string_of_int (List.sort compare participants)));
  tagged "context" context;
  tagged "nonce" nonce;
  Digestif.SHA256.(to_raw_string (digest_string (Buffer.contents b)))

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
  culprits : peer list;
  round : int;
  detail : string;
}

let abort_code_to_string : abort_code -> string = function
  | `Timeout -> "timeout"
  | `Bad_message -> "bad message"
  | `Bad_proof -> "bad proof"
  | `Bad_share -> "bad share"
  | `Equivocation -> "equivocation"
  | `Cancelled -> "cancelled"
  | `Nonce_already_used -> "nonce already used"
  | `Internal -> "internal error"

let pp_abort ppf a =
  Format.fprintf ppf "@[<h>abort in round %d: %s" a.round
    (abort_code_to_string a.code);
  (match a.culprits with
  | [] -> ()
  | cs ->
      Format.fprintf ppf " (culprits: %s)"
        (String.concat ", " (List.map string_of_int cs)));
  if a.detail <> "" then Format.fprintf ppf " -- %s" a.detail;
  Format.fprintf ppf "@]"

type 'msg input = Start | Recv of 'msg | Timeout of int | Cancel

type ('msg, 'out) event =
  | Send of { to_ : [ `All | `Peer of peer ]; msg : 'msg; private_ : bool }
  | Output of 'out
  | Aborted of abort

module Slots = struct
  (* An association list keyed by (round, peer). Participant counts are small -- the
     wire format caps them at 65535 and real deployments are far below that -- so the
     linear lookup is not worth trading for a functor over a Map. *)
  type t = {
    rounds : int;
    peers : peer list;
    cells : ((int * peer) * string) list;
  }

  let create ~rounds ~peers =
    { rounds; peers = List.sort_uniq compare peers; cells = [] }

  let peers t = t.peers

  let put t ~round ~from payload =
    if round < 0 || round >= t.rounds then `Bad_round
    else if not (List.mem from t.peers) then `Unknown_peer
    else
      match List.assoc_opt (round, from) t.cells with
      | Some existing ->
          if String.equal existing payload then `Duplicate else `Equivocation
      | None -> `Stored { t with cells = ((round, from), payload) :: t.cells }

  let get t ~round ~from = List.assoc_opt (round, from) t.cells

  let filled t ~round =
    List.filter_map
      (fun p -> Option.map (fun v -> (p, v)) (get t ~round ~from:p))
      t.peers

  let missing t ~round =
    List.filter (fun p -> get t ~round ~from:p = None) t.peers

  let complete t ~round = missing t ~round = []
  let wipe t = { t with cells = [] }
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
  val status : t -> [ `Running | `Done | `Aborted of abort ]
  val wipe : t -> unit
end
