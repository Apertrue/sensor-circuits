// CaptureAggregator -- ONE proof per capture (image_aggregator pattern).
//
// Recursively verifies, in a single ~150k-gate UltraHonk proof:
//   1. zk_attest_delegate (415k): a key minted by a genuine copy of this
//      app on genuine Apple hardware authorized the PUBLIC binding message
//      (cert private, CA-1 pinned inside the inner circuit)
//   2. prnu_bind_v3 (170k): the photo's sensor bits belong to an enrolled
//      device under the PUBLIC registry root (anonymous membership)
//
// The inner public values are RECONSTRUCTED from this circuit's own public
// inputs, so the aggregate exposes exactly what the two proofs exposed --
// every existing verifier check keeps working against one proof.
//
// Public outputs: capture_commitment (Poseidon2 over root + binding-msg
// hash + aaguid hash) and both inner VK hashes (verifier pins them).

use dep::bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use dep::poseidon::poseidon2::Poseidon2;

// zk_attest_delegate: 144 binding_msg bytes + 16 aaguid bytes (as fields)
global DELEGATE_PUBLIC_VALUES: u32 = 160;

fn main(
    binding_msg: pub [Field; 144],
    aaguid: pub [Field; 16],
    registry_root: pub Field,
    proof_delegate: UltraHonkZKProof,
    vk_delegate: UltraHonkVerificationKey,
    vk_delegate_hash: Field,
    proof_v3: UltraHonkZKProof,
    vk_v3: UltraHonkVerificationKey,
    vk_v3_hash: Field,
) -> pub (Field, Field, Field) {
    // Inner public values, rebuilt from OUR public inputs (no free witness).
    let mut delegate_publics: [Field; DELEGATE_PUBLIC_VALUES] = [0; DELEGATE_PUBLIC_VALUES];
    for i in 0..144 {
        delegate_publics[i] = binding_msg[i];
    }
    for i in 0..16 {
        delegate_publics[144 + i] = aaguid[i];
    }
    verify_honk_proof(vk_delegate, proof_delegate, delegate_publics, vk_delegate_hash);
    verify_honk_proof(vk_v3, proof_v3, [registry_root], vk_v3_hash);

    let binding_hash = Poseidon2::hash(binding_msg, 144);
    let aaguid_hash = Poseidon2::hash(aaguid, 16);
    let capture_commitment =
        Poseidon2::hash([registry_root, binding_hash, aaguid_hash, vk_delegate_hash, vk_v3_hash], 5);
    (capture_commitment, vk_delegate_hash, vk_v3_hash)
}
