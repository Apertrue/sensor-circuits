// zkAppAttest P-384 port spike (task 1 of the zkAppAttest track).
// Statement: signature (r,s) by pubkey (x,y) over message_hash verifies.
// This is the CA-1 -> credCert TBS signature shape from App Attest; the
// full circuit (SHA of TBS, nonce ext, authData) lands once this proves
// under nargo beta.20 + bb 5.0.0-nightly.20260324.

mod crypto;
mod crypto_utils;

fn main(
    message_hash: [u8; 48],
    pubkey_x: pub [u8; 48],
    pubkey_y: pub [u8; 48],
    sig_r: [u8; 48],
    sig_s: [u8; 48],
) {
    assert(crypto_utils::verify_ecdsa_p384(message_hash, pubkey_x, pubkey_y, sig_r, sig_s));
}
