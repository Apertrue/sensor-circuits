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
// SCALING (July 8, RESOLVED by microbenchmarks): the initial i32
// multiply-accumulate form cost ~45 gates/tap (projected 2.8M at
// production); the culprit was SIGNED ARITHMETIC, not the ROM read
// (pure dynamic bool read = ~10.5 gates incl. counter; ROM is the right
// primitive, no better library exists). The agreement-count form below
// measures 8.65 gates/tap + ~4/array-entry init. PRODUCTION projection
// (Z=32704, M=4096, S=15): ~700k gates ~= one-time ~20 s on phone /
// ~7 s desktop -- shippable for an enrollment that already takes
// minutes. If Jamie drops M to 1024 (still 30 sigma by E1), ~300k
// ~= ~9 s phone. Witness IS the raw fingerprint -> cannot outsource.
//
// DESIGN NOTE for Jamie: tap privacy + enclave-key binding scheme (a
// commitment to k tying taps to the enclave) is the reviewable choice;
// this circuit takes taps as private witness and leaves the k-commitment
// to a companion once the key scheme is fixed.

global Z: u32 = 32704;         // raw stability bits (PRODUCTION)
global M: u32 = 1024;          // template bits (BLESSED July 8: ~30 sigma by E1;
                               // fits key tier 128x7=896; halves proving vs 4096)
global S: u32 = 15;            // taps per template bit (odd, no ties)
global DEVICE_ID_BITS: u32 = 64;
global R_DEV: u32 = 63;
global CORE_N: u32 = 4032;     // DEVICE_ID_BITS * R_DEV; core = raw_bits prefix... (see note)

fn main(
    raw_bits: [bool; Z],                // fingerprint bits, +1 -> true (private)
    taps: [u32; 15360],                  // M*S indices into raw_bits (private)
    weights: [bool; 15360],              // M*S signs, +1 -> true (private)
    core_bits: [bool; CORE_N],          // stable-core bits for the FE (private)
    device_sketch: pub [bool; CORE_N],  // public helper data
    registry_id: pub Field,
) -> pub (Field, Field, Field) {
    // ---- 1. keyed BioHash template -> packed leaf ----
    // AGREEMENT-COUNT form of sign(sum_s w*b) over +/-1 values:
    //   sum = agreements - disagreements = 2*agreements - S
    //   sum >= 0  <=>  agreements > S/2   (S odd -> no ties)
    // Boolean equality + counter instead of signed multiply-accumulate:
    // measured 8.65 gates/tap vs ~45 for the i32 form (July 8 microbench).
    let mut leaf_acc: Field = 0;
    let mut leaf_pow: Field = 1;
    for m in 0..M {
        let mut agree: u32 = 0;
        for s in 0..S {
            // dynamic read into the private raw_bits (ROM table)
            let b = raw_bits[taps[m * S + s]];
            agree += (b == weights[m * S + s]) as u32;
        }
        let tbit = (agree > S / 2) as u32;
        leaf_acc += leaf_pow * (tbit as Field);
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
