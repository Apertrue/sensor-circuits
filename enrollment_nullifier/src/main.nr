// Enrollment nullifier (CANCELABLE.md OP1, decision 2) -- the one-time
// per-device proof that makes registration Sybil-resistant WITHOUT
// revealing the sensor.
//
// Statement (private core_bits; public device_sketch, registry_id):
//   1. a SECOND fuzzy extractor over the stable sensor CORE recovers a
//      deterministic DEVICE_ID_BITS device-ID -- same sensor, any
//      enrollment/transform key => SAME device-ID (cross-enroll BER
//      0.002-0.009 error-corrects at R_DEV=63; impostor recovers a
//      DIFFERENT id).  Same code-offset repetition FE as prnu_key v1,
//      applied to the core instead of the key tier.
//   2. nullifier = PRF(device_id, registry_id) = pedersen([id, reg]).
//      Registry stores the nullifier -> a re-enrolling sensor collides
//      (duplicate refused); DISTINCT registry_ids give unlinkable
//      nullifiers across registries.
//   3. device_commitment = pedersen([device_id]) -- ties this proof to a
//      claimed identity the registry can also carry.
//
// NOTE (de-scoped, measured 2026-07-09): step 1's cross-enrollment device-ID
// recovery was measured DEAD on hardware -- two enrolments of the SAME sensor
// linked at BER ~0.451 (chance), because the core is ordered by each
// enrolment's own stability ranking (position i is a different pixel each
// time). So this proof does NOT provide cross-enrollment identity or real
// Sybil resistance: it gives verbatim-duplicate refusal + rotation only, and
// duplicate/Sybil policy is layered on the enrolment attestation instead. The
// 64-bit device-ID is also below cryptographic margin. Not load-bearing in the
// shipped system (registration is near-open in the MVP; see paperB threat model).
//
// PARAMETERS from the July-7 measurement (OP1): core >= 4096, r >= 63,
// device-ID 64 bits.  Set as globals -- Jamie's final calibration only
// changes these constants.  Defaults below are the measured-safe values
// (predicted enrollment failure ~0 at core>=4096, r>=63).
//
// The heavier leaf<->template<->device-ID consistency binding (secret
// taps via ROM tables, ~50-130k gates) layers ON TOP of this core proof;
// this circuit is the nullifier the verifier gate needs (see
// docs/CANCELABLE.md 5c OP2 for the split).

global DEVICE_ID_BITS: u32 = 64;   // fuzzy-recovered canonical device-ID
global R_DEV: u32 = 63;            // repetition folds (odd; >= 63 measured)
global CORE_N: u32 = 4032;         // DEVICE_ID_BITS * R_DEV (<= 16384 core)

fn main(
    core_bits: [bool; CORE_N],
    device_sketch: pub [bool; CORE_N],
    registry_id: pub Field,
) -> pub (Field, Field) {
    // ---- 1. recover the device-ID: majority-vote code-offset FE ----
    let mut id_field: Field = 0;
    let mut pow: Field = 1;
    for i in 0..DEVICE_ID_BITS {
        let mut count: u32 = 0;
        for j in 0..R_DEV {
            let x = device_sketch[i * R_DEV + j] ^ core_bits[i * R_DEV + j];
            count += x as u32;
        }
        let bit = (count > (R_DEV / 2)) as u32;
        id_field += pow * (bit as Field);
        pow *= 2;
    }

    // ---- 2. per-registry nullifier + 3. device commitment ----
    let nullifier = std::hash::pedersen_hash([id_field, registry_id]);
    let device_commitment = std::hash::pedersen_hash([id_field]);
    (nullifier, device_commitment)
}
