// zkAppAttest (docs/ZK_ATTEST.md): prove that a PRIVATE App Attest
// credential certificate, issued by Apple's App Attestation CA 1 (pinned),
// attests THIS app (pinned appID hash) over the PUBLIC challenge -- without
// revealing the certificate, the credential key, or anything linkable.
//
// Statement, given public (challenge, aaguid):
//   exists credCert TBS, sig (r,s), authData such that
//   1. ECDSA-P384_CA1(SHA256(TBS), r, s) verifies          -- Apple issued it
//   2. TBS[nonce_off] == SHA256(authData || SHA256(challenge))
//      behind the Apple nonce OID                          -- it attests THIS challenge
//   3. keyID = SHA256(leaf pubkey point in TBS) == authData credentialId
//   4. authData.rpIdHash == SHA256(appID), counter == 0,
//      authData.aaguid == aaguid                           -- THIS app, fresh key
//
// Verifier obligations OUTSIDE the circuit: CA-1 chains to Apple's root
// (static, checked once) and aaguid policy (dev vs production).

mod constants;
mod crypto;
mod crypto_utils;

use constants::{APP_ID_HASH, CA1_X, CA1_Y, NONCE_DER_PREFIX};
use sha256::sha256_var;

global TBS_MAX: u32 = 1024;
global AUTH_DATA_LEN: u32 = 164;
global CHALLENGE_LEN: u32 = 66;

fn main(
    tbs: [u8; TBS_MAX],
    tbs_len: u32,
    sig_r: [u8; 48],
    sig_s: [u8; 48],
    auth_data: [u8; AUTH_DATA_LEN],
    nonce_offset: u32,
    leaf_point_offset: u32,
    challenge: pub [u8; CHALLENGE_LEN],
    aaguid: pub [u8; 16],
) {
    // ---- 1. Apple CA-1 (pinned) signed this TBS: P-384 over SHA-256 ----
    assert(tbs_len <= TBS_MAX);
    let tbs_hash: [u8; 32] = sha256_var(tbs, tbs_len);
    // e = int(SHA-256 digest), left-padded into the 48-byte P-384 scalar
    let mut e: [u8; 48] = [0; 48];
    for i in 0..32 {
        e[i + 16] = tbs_hash[i];
    }
    assert(
        crypto_utils::verify_ecdsa_p384(e, CA1_X, CA1_Y, sig_r, sig_s),
        "credCert not issued by Apple App Attestation CA 1",
    );

    // ---- 2. nonce extension binds authData + challenge into the cert ----
    // nonce = SHA256(authData || SHA256(challenge)), embedded in TBS behind
    // the Apple nonce OID (structural DER prefix asserted, not just value).
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
    // 03 42 00 = BIT STRING(66), 0 unused bits, then the uncompressed point.
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

    // ---- 4. authData fixed layout (attest_validate.py, in-circuit) ----
    // rpIdHash(32) | flags(1) | counter(4) | aaguid(16) | credIdLen(2) | credId(32)
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
}
