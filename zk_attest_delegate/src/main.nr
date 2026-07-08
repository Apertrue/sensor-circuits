// zkAppAttest DELEGATION (docs/ZK_ATTEST.md, task 5): the per-capture proof.
//
// Statement, given public (binding_msg, aaguid):
//   exists credCert TBS, CA-1 sig, authData, enroll_challenge, assertion
//   such that
//   1-4. the zk_attest statement holds (Apple CA-1 issued the private
//        credCert; its nonce commits authData + enroll_challenge; keyID =
//        SHA256(credential key) = credentialId; rpIdHash = SHA256(appID))
//        -- with enroll_challenge PRIVATE here (it was public at
//        registration; the per-capture proof need not reveal it)
//   5.   an App Attest ASSERTION by that same credential key signs
//        SHA256(assert_auth_data || SHA256(binding_msg)) and
//        assert_auth_data.rpIdHash == SHA256(appID)
//
// => "this capture's binding message was authorized by a key that a
//    genuine copy of THIS app minted on genuine Apple hardware" -- ONE
//    Apple contact ever (enrollment); Apple sees no per-capture calls;
//    verifiers see nothing linkable across captures.
//
// Verifier obligations OUTSIDE the circuit: CA-1 chains to Apple's root
// (static) and aaguid policy (dev vs production).

mod constants;
mod crypto;
mod crypto_utils;

use constants::{APP_ID_HASH, CA1_X, CA1_Y, NONCE_DER_PREFIX};
use sha256::sha256_var;

global TBS_MAX: u32 = 1024;
global AUTH_DATA_LEN: u32 = 164;
global CHALLENGE_LEN: u32 = 66;
// rawSHA256(32) | heicSHA256(32) | pdq(32) | beacon(40) | timestamp(8)
global BINDING_MSG_LEN: u32 = 144;
// rpIdHash(32) | flags(1) | counter(4)
global ASSERT_AD_LEN: u32 = 37;

fn main(
    tbs: [u8; TBS_MAX],
    tbs_len: u32,
    sig_r: [u8; 48],
    sig_s: [u8; 48],
    auth_data: [u8; AUTH_DATA_LEN],
    nonce_offset: u32,
    leaf_point_offset: u32,
    challenge: [u8; CHALLENGE_LEN], // enrollment challenge -- PRIVATE here
    assert_auth_data: [u8; ASSERT_AD_LEN],
    assert_sig: [u8; 64],
    binding_msg: pub [u8; BINDING_MSG_LEN],
    aaguid: pub [u8; 16],
) {
    // ---- 1. Apple CA-1 (pinned) signed this TBS: P-384 over SHA-256 ----
    assert(tbs_len <= TBS_MAX);
    let tbs_hash: [u8; 32] = sha256_var(tbs, tbs_len);
    let mut e: [u8; 48] = [0; 48];
    for i in 0..32 {
        e[i + 16] = tbs_hash[i];
    }
    assert(
        crypto_utils::verify_ecdsa_p384(e, CA1_X, CA1_Y, sig_r, sig_s),
        "credCert not issued by Apple App Attestation CA 1",
    );

    // ---- 2. nonce extension binds authData + enroll challenge ----
    let client_hash: [u8; 32] = sha256_var(challenge, CHALLENGE_LEN);
    let mut nonce_msg: [u8; 196] = [0; 196]; // AUTH_DATA_LEN + 32
    for i in 0..AUTH_DATA_LEN {
        nonce_msg[i] = auth_data[i];
    }
    for i in 0..32 {
        nonce_msg[AUTH_DATA_LEN + i] = client_hash[i];
    }
    let nonce: [u8; 32] = sha256_var(nonce_msg, 196);
    assert(nonce_offset >= 19);
    assert(nonce_offset + 32 <= tbs_len, "nonce outside signed TBS");
    for i in 0..19 {
        assert(tbs[nonce_offset - 19 + i] == NONCE_DER_PREFIX[i], "nonce DER context");
    }
    for i in 0..32 {
        assert(tbs[nonce_offset + i] == nonce[i], "nonce mismatch: challenge not attested");
    }

    // ---- 3. credential key: keyID == SHA256(SPKI point) == credentialId ----
    assert(leaf_point_offset >= 3);
    assert(leaf_point_offset + 65 <= tbs_len, "leaf key outside signed TBS");
    assert(tbs[leaf_point_offset - 3] == 0x03, "SPKI BIT STRING tag");
    assert(tbs[leaf_point_offset - 2] == 0x42, "SPKI BIT STRING length");
    assert(tbs[leaf_point_offset - 1] == 0x00, "SPKI unused bits");
    let mut point: [u8; 65] = [0; 65];
    for i in 0..65 {
        point[i] = tbs[leaf_point_offset + i];
    }
    assert(point[0] == 0x04, "uncompressed point tag");
    let key_id: [u8; 32] = sha256_var(point, 65);

    // ---- 4. authData fixed layout ----
    for i in 0..32 {
        assert(auth_data[i] == APP_ID_HASH[i], "rpIdHash != SHA256(appID)");
    }
    for i in 0..4 {
        assert(auth_data[33 + i] == 0, "counter != 0 at attestation");
    }
    for i in 0..16 {
        assert(auth_data[37 + i] == aaguid[i], "aaguid mismatch");
    }
    assert(auth_data[53] == 0, "credIdLen high byte");
    assert(auth_data[54] == 32, "credIdLen low byte");
    for i in 0..32 {
        assert(auth_data[55 + i] == key_id[i], "credentialId != SHA256(credential key)");
    }

    // ---- 5. DELEGATION: the attested key asserts this capture ----
    // App Attest assertion: sig over SHA256(assertAuthData || SHA256(clientData)),
    // clientData = the capture binding message (public input).
    for i in 0..32 {
        assert(assert_auth_data[i] == APP_ID_HASH[i], "assertion rpIdHash != SHA256(appID)");
    }
    let binding_hash: [u8; 32] = sha256_var(binding_msg, BINDING_MSG_LEN);
    let mut assert_msg: [u8; 69] = [0; 69]; // ASSERT_AD_LEN + 32
    for i in 0..ASSERT_AD_LEN {
        assert_msg[i] = assert_auth_data[i];
    }
    for i in 0..32 {
        assert_msg[ASSERT_AD_LEN + i] = binding_hash[i];
    }
    // Apple signs the NONCE as a message: the ECDSA digest is
    // SHA256(nonce) = SHA256(SHA256(assertAuthData || clientDataHash))
    // (verified against a real on-device assertion, July 8).
    let assert_nonce: [u8; 32] = sha256_var(assert_msg, 69);
    let assert_digest: [u8; 32] = sha256_var(assert_nonce, 32);
    let mut pk_x: [u8; 32] = [0; 32];
    let mut pk_y: [u8; 32] = [0; 32];
    for i in 0..32 {
        pk_x[i] = point[1 + i];
        pk_y[i] = point[33 + i];
    }
    assert(
        std::ecdsa_secp256r1::verify_signature(pk_x, pk_y, assert_sig, assert_digest),
        "assertion not signed by the attested credential key",
    );
}
