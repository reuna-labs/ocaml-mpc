let () =
  Alcotest.run "mpc"
    (Suite_group.suites @ Suite_sharing.suites @ Suite_frost.suites
   @ Suite_session.suites @ Suite_dkg.suites @ Suites_ed25519.suites
   @ Suites_secp256k1.suites @ Suite_codec.suites @ Suite_props.suites
   @ Suite_xmd.suites @ Suite_specpin.suites)
