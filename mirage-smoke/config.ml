open Mirage

(* Compute-only: no network and no block device. The point is to prove that the
   protocol core, the ciphersuite and the transport link and run under Solo5, not to
   exercise a device stack. *)
let main =
  main "Unikernel.Main" job
    ~packages:
      [
        package "mpc" ~libs:[ "mpc"; "mpc.ed25519"; "mpc.secp256k1"; "mpc.frost" ];
        package "mpc-lwt";
        package "mirage-crypto-rng-mirage";
      ]

let () = register "mpc_smoke" [ main ]
