// Cross-implementation validation between ocaml-mpc and ZcashFoundation/frost.
//
// Three subcommands, all speaking hex on stdout/argv so the OCaml side needs no
// serialisation agreement beyond "bytes":
//
//   gen      -- their trusted-dealer keygen; emits the group key and every signing
//               share, so ocaml-mpc can sign with key material it did not produce.
//   sign     -- their full keygen + threshold sign; emits a signature for ocaml-mpc
//               to verify.
//   verify   -- verify a (key, message, signature) triple with their verifier.



fn hex_of(b: &[u8]) -> String { hex::encode(b) }

// The three commands are identical apart from the ciphersuite, so generate them for
// each rather than keeping two copies that can drift.
macro_rules! suite_cmds {
    ($m:ident, $frost:path) => {
        mod $m {
            use $frost as frost;
            use rand::rngs::OsRng;
            use std::collections::BTreeMap;
            use super::hex_of;


pub fn cmd_gen(t: u16, n: u16, msg: &str) {
    let mut rng = OsRng;
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(n, t, frost::keys::IdentifierList::Default, &mut rng)
            .expect("dealer keygen");
    let mut out = serde_json::Map::new();
    out.insert("group_public_key".into(),
        hex_of(&pubkeys.verifying_key().serialize().unwrap()).into());
    out.insert("message".into(), msg.to_string().into());
    let mut arr = Vec::new();
    for (id, share) in shares.iter() {
        let kp = frost::keys::KeyPackage::try_from(share.clone()).expect("key package");
        let mut e = serde_json::Map::new();
        e.insert("identifier".into(), hex_of(&id.serialize()).into());
        e.insert("signing_share".into(),
            hex_of(&kp.signing_share().serialize()).into());
        e.insert("verifying_share".into(),
            hex_of(&kp.verifying_share().serialize().unwrap()).into());
        arr.push(serde_json::Value::Object(e));
    }
    out.insert("shares".into(), serde_json::Value::Array(arr));
    println!("{}", serde_json::Value::Object(out));
}

pub fn cmd_sign(t: u16, n: u16, msg: &str) {
    let mut rng = OsRng;
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(n, t, frost::keys::IdentifierList::Default, &mut rng)
            .expect("dealer keygen");
    let key_packages: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let signers: Vec<_> = key_packages.keys().take(t as usize).cloned().collect();

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &signers {
        let kp = &key_packages[id];
        let (n1, c1) = frost::round1::commit(kp.signing_share(), &mut rng);
        nonces.insert(*id, n1);
        commitments.insert(*id, c1);
    }
    let msg_bytes = msg.as_bytes();
    let package = frost::SigningPackage::new(commitments, msg_bytes);
    let mut sig_shares = BTreeMap::new();
    for id in &signers {
        let s = frost::round2::sign(&package, &nonces[id], &key_packages[id]).expect("sign");
        sig_shares.insert(*id, s);
    }
    let group_sig = frost::aggregate(&package, &sig_shares, &pubkeys).expect("aggregate");
    pubkeys.verifying_key().verify(msg_bytes, &group_sig).expect("their own verify");

    let mut out = serde_json::Map::new();
    out.insert("group_public_key".into(),
        hex_of(&pubkeys.verifying_key().serialize().unwrap()).into());
    out.insert("message".into(), msg.to_string().into());
    out.insert("signature".into(), hex_of(&group_sig.serialize().unwrap()).into());
    println!("{}", serde_json::Value::Object(out));
}

pub fn cmd_verify(pk_hex: &str, msg: &str, sig_hex: &str) {
    let pk_bytes = hex::decode(pk_hex).expect("pk hex");
    let sig_bytes = hex::decode(sig_hex).expect("sig hex");
    let vk = frost::VerifyingKey::deserialize(&pk_bytes).expect("verifying key");
    let sig = frost::Signature::deserialize(&sig_bytes).expect("signature");
    match vk.verify(msg.as_bytes(), &sig) {
        Ok(()) => { println!("ACCEPT"); }
        Err(e) => { println!("REJECT {e}"); std::process::exit(1); }
    }
}

// Their DKG round 1, emitted so ocaml-mpc can verify the proof of knowledge with its
// own recomputed challenge. If the two challenge constructions differ by a single
// byte, every verification below fails.
pub fn cmd_dkg1(t: u16, n: u16) {
    let mut rng = OsRng;
    let mut arr = Vec::new();
    for i in 1..=n {
        let id = frost::Identifier::try_from(i).unwrap();
        let (_secret, pkg) = frost::keys::dkg::part1(id, n, t, &mut rng).expect("dkg part1");
        let mut e = serde_json::Map::new();
        e.insert("identifier".into(), hex_of(&id.serialize()).into());
        let coeffs: Vec<serde_json::Value> = pkg
            .commitment()
            .serialize()
            .unwrap()
            .iter()
            .map(|c| serde_json::Value::String(hex_of(c)))
            .collect();
        e.insert("commitment".into(), serde_json::Value::Array(coeffs));
        // Serialize the proof as a whole: it is R || z, 64 bytes, exactly the layout
        // of a Schnorr signature, which is what it is.
        e.insert("pok".into(),
            hex_of(&pkg.proof_of_knowledge().serialize().unwrap()).into());
        arr.push(serde_json::Value::Object(e));
    }
    println!("{}", serde_json::Value::Array(arr));
}

        }
    };
}

suite_cmds!(ed25519, frost_ed25519);
suite_cmds!(secp256k1, frost_secp256k1);

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some(s) => {
            let (suite, cmd) = s.split_once(':').unwrap_or(("ed25519", s));
            macro_rules! dispatch { ($m:ident) => {
                match cmd {
                    "gen"    => $m::cmd_gen(a[2].parse().unwrap(), a[3].parse().unwrap(), &a[4]),
                    "sign"   => $m::cmd_sign(a[2].parse().unwrap(), a[3].parse().unwrap(), &a[4]),
                    "verify" => $m::cmd_verify(&a[2], &a[3], &a[4]),
                    "dkg1"   => $m::cmd_dkg1(a[2].parse().unwrap(), a[3].parse().unwrap()),
                    _ => { eprintln!("unknown command {cmd}"); std::process::exit(2); }
                }
            }}
            match suite {
                "ed25519" => dispatch!(ed25519),
                "secp256k1" => dispatch!(secp256k1),
                _ => { eprintln!("unknown suite {suite}"); std::process::exit(2); }
            }
        }
        _ => { eprintln!("usage: [SUITE:]CMD ...  SUITE=ed25519|secp256k1  CMD=gen T N MSG|sign T N MSG|verify PK MSG SIG|dkg1 T N"); std::process::exit(2); }
    }
}
