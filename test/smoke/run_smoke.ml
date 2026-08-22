(* Runs the unikernel's smoke checks on the host.

   [Unikernel.Main.start] expects the randomness source to be initialised already: in a
   unikernel Mirage's generated main does it, and doing it twice is an error. Here that
   is this file's job. *)

let () =
  Mirage_crypto_rng_unix.use_default ();
  match Lwt_main.run (Unikernel.Main.start ()) with
  | () -> ()
  | exception e ->
      Printf.eprintf "smoke test raised: %s\n" (Printexc.to_string e);
      exit 1
