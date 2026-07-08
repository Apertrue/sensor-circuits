use dep::bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};

fn main(
    y: pub Field,
    proof: UltraHonkZKProof,
    vk: UltraHonkVerificationKey,
    vk_hash: Field,
) {
    verify_honk_proof(vk, proof, [y], vk_hash);
}
