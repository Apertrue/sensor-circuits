// Cancelable-PRNU enrollment (CANCELABLE.md OP2) -- the one-time proof
// that registers a cancelable TEMPLATE leaf instead of the raw fingerprint.
//
// WHY (survives the Sybil de-scope, CANCELABLE.md 5f): PRNU is present in
// every published photo, so an adversary can ESTIMATE a target's raw
// fingerprint from their photos (fingerprint-copy attack). The membership
// proof takes fresh bits as private input, so what stops a forger is
// knowledge of a valid PREIMAGE to the enrolled commitment. Registering
// commit(T_k(bits)) with k enclave-secret means estimated raw bits are
// useless without k -> forgery blocked. It also gives rotation/burn-notice
// (leak a template -> rotate k, re-enroll) and cross-registry
// compartmentalisation (distinct k per registry). None of this is Sybil.
//
// Statement (private raw_bits, taps, weights; public leaf):
//   LEAF = commitment to template = keyed BioHash of raw_bits:
//     template[m] = sign( sum_s weights[m][s] * raw_bits[taps[m][s]] )
//   Taps/weights are PRIVATE (enclave-derived) -- OP2: public taps would
//   let raw bits alone recompute templates, breaking compartmentalisation.
//
// Verification proofs (every photo) stay the UNCHANGED v1/v2/v3 circuits
// fed template bits off-circuit; only THIS enrollment proof is heavier.
//
// SCALING (July 8, microbenchmarks): the agreement-count form is 8.65
// gates/tap (the i32 multiply-accumulate was ~45 -- signed-arith range
// checks, not the ROM read). PRODUCTION M=1024 measured 290,534 gates
// with the device-ID half; template-only is smaller. Witness IS the raw
// fingerprint -> cannot outsource; one-time at enrollment (~seconds).
//
// DESIGN NOTE for Jamie: tap privacy + enclave-key binding (a commitment
// to k tying taps to the enclave) is the reviewable choice; this circuit
// takes taps as private witness and leaves the k-commitment to a companion
// once the key scheme is fixed.
//
// Sybil de-scoped (CANCELABLE.md 5f): the device-ID FE + nullifier were
// removed -- device-uniqueness is out of scope (fingerprint canonicalisation
// can't give it, and it isn't needed for the core claim). This circuit is
// now template-registration only.

global Z: u32 = 32704;         // raw stability bits (PRODUCTION)
global M: u32 = 1024;          // template bits (BLESSED July 8: ~30 sigma by E1;
                               // fits key tier 128x7=896; halves proving vs 4096)
global S: u32 = 15;            // taps per template bit (odd, no ties)

fn main(
    raw_bits: [bool; Z],            // fingerprint bits, +1 -> true (private)
    taps: [u32; 15360],            // M*S indices into raw_bits (private)
    weights: [bool; 15360],        // M*S signs, +1 -> true (private)
) -> pub Field {
    // keyed BioHash template -> packed leaf.
    // AGREEMENT-COUNT form of sign(sum_s w*b) over +/-1 values:
    //   sum = 2*agreements - S ;  sum >= 0  <=>  agreements > S/2  (S odd).
    // Boolean equality + counter, no signed arithmetic (5x cheaper).
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
    std::hash::pedersen_hash([leaf_acc])
}
