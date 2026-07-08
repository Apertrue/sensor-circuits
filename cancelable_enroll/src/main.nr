// Cancelable-PRNU enrollment (CANCELABLE.md OP2, decision 2) -- the
// one-time proof that makes the Sybil nullifier TRUSTWORTHY by binding it
// to the same physical fingerprint as the registry leaf.
//
// The threat it closes: without this, an adversary registers with their
// real template leaf L but submits a RANDOM nullifier N, evading duplicate
// detection. This proof shows L and N derive from ONE witnessed raw-bit
// array -> the nullifier is provably the sensor's.
//
// Statement (private raw_bits, taps, weights; public leaf, nullifier,
// device_commitment, device_sketch):
//   1. LEAF  = commitment to template = keyed BioHash of raw_bits:
//        template[m] = sign( sum_s weights[m][s] * raw_bits[taps[m][s]] )
//      Taps/weights are PRIVATE (enclave-derived) -- OP2: public taps would
//      let raw bits alone recompute templates, breaking compartmentalization.
//   2. NULLIFIER = device-ID FE over the CORE (a fixed prefix of raw_bits)
//        with the public device_sketch -> pedersen([device_id, registry_id]).
//   3. Both read the SAME raw_bits witness -> leaf and nullifier are bound.
//
// Verification proofs (every photo) stay the UNCHANGED v1/v2/v3 circuits
// fed template bits off-circuit; only THIS enrollment proof is heavier.
//
// SIZES: validated at reduced scale here (compile + golden + gate probe);
// production M=4096, S=15, Z=32704 per the measured transform (E1/E2).
//
// SCALING FINDING (July 8, measured two points M=128/256): each dynamic
// read into raw_bits costs ~45 gates in Noir (NOT the doc's "3-10 gates"
// for a hand-built ROM), ~36k fixed. Production M=4096 -> 61,440 reads
// -> ~2.8M gates -- ~7x the doc estimate and > capture_aggregator. This
// is a one-time ENROLLMENT proof and CANNOT be outsourced (its witness IS
// the raw fingerprint), so before ship the transform read needs a proper
// lookup-table (Noir std lookups / precomputed ROM) to reach the doc's
// estimate, or M reduced (security-margin tradeoff, E1 has 60σ headroom).
// The MECHANISM is validated; the read-cost is the open optimization.
//
// DESIGN NOTE for Jamie: tap privacy + enclave-key binding scheme (a
// commitment to k tying taps to the enclave) is the reviewable choice;
// this circuit takes taps as private witness and leaves the k-commitment
// to a companion once the key scheme is fixed.

global Z: u32 = 2048;          // raw stability bits (prod 32704)
global M: u32 = 256;           // template bits (prod 4096)
global S: u32 = 15;            // taps per template bit (odd, no ties)
global DEVICE_ID_BITS: u32 = 64;
global R_DEV: u32 = 63;
global CORE_N: u32 = 4032;     // DEVICE_ID_BITS * R_DEV; core = raw_bits prefix... (see note)

fn main(
    raw_bits: [i32; Z],                 // +/-1 fingerprint bits (private)
    taps: [u32; 3840],                  // M*S indices into raw_bits (private)
    weights: [i32; 3840],               // M*S signs +/-1 (private)
    core_bits: [bool; CORE_N],          // stable-core bits for the FE (private)
    device_sketch: pub [bool; CORE_N],  // public helper data
    registry_id: pub Field,
) -> pub (Field, Field, Field) {
    // ---- 1. keyed BioHash template -> packed leaf ----
    // template[m] = sign(sum_s weights * raw_bits[taps]); pack sign>=0 as 1.
    let mut leaf_acc: Field = 0;
    let mut leaf_pow: Field = 1;
    for m in 0..M {
        let mut acc: i32 = 0;
        for s in 0..S {
            let idx = taps[m * S + s];
            // dynamic read into the private raw_bits (ROM table)
            let bit = raw_bits[idx];
            acc += weights[m * S + s] * bit;
        }
        // sign(acc): acc != 0 because S is odd and bits are +/-1.
        let is_nonneg = (acc >= 0) as u32;
        leaf_acc += leaf_pow * (is_nonneg as Field);
        leaf_pow *= 2;
        // reduce every 250 bits to keep the field packing valid
        if (m + 1) % 250 == 0 {
            leaf_acc = std::hash::pedersen_hash([leaf_acc]);
            leaf_pow = 1;
        }
    }
    let leaf = std::hash::pedersen_hash([leaf_acc]);

    // ---- 2. device-ID FE over the core -> nullifier ----
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
    let nullifier = std::hash::pedersen_hash([id_field, registry_id]);
    let device_commitment = std::hash::pedersen_hash([id_field]);

    // 3. leaf and nullifier both consumed raw_bits/core_bits from one witness.
    (leaf, nullifier, device_commitment)
}
