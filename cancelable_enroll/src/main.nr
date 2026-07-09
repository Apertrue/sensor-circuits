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

// v2 registry-leaf constants -- MUST mirror circuits/registry_helper exactly:
// the point of the 2026-07-09 rewire is that the public output below IS the
// leaf sitting in the verifier's registry, so this proof speaks about the
// REGISTERED value, not a free-floating template commitment.
global KEY_BITS: u32 = 128;
global R: u32 = 7;
global N_KEY: u32 = 896;       // KEY_BITS * R; template[0..896] feeds the FE
global PACK: u32 = 224;
global NCHUNK: u32 = 4;

fn main(
    raw_bits: [bool; Z],            // fingerprint bits, +1 -> true (private)
    taps: [u32; 15360],            // M*S indices into raw_bits (private)
    weights: [bool; 15360],        // M*S signs, +1 -> true (private)
    sketch: [bool; N_KEY],         // code-offset sketch over template[0..896]
                                   // (private; its hash is bound inside leaf)
) -> pub Field {
    // 1. keyed BioHash template.
    // AGREEMENT-COUNT form of sign(sum_s w*b) over +/-1 values:
    //   sum = 2*agreements - S ;  sum >= 0  <=>  agreements > S/2  (S odd).
    // Boolean equality + counter, no signed arithmetic (5x cheaper).
    let mut template: [bool; M] = [false; M];
    for m in 0..M {
        let mut agree: u32 = 0;
        for s in 0..S {
            // dynamic read into the private raw_bits (ROM table)
            let b = raw_bits[taps[m * S + s]];
            agree += (b == weights[m * S + s]) as u32;
        }
        template[m] = agree > S / 2;
    }

    // 2. the REGISTERED v2 leaf from that template -- byte-for-byte the
    // registry_helper computation: decode the key from template[0..896] vs
    // the sketch (r=7 majority), commit the key, hash the sketch chunks,
    // leaf = H(commit, sketch_hash).
    let mut key_field: Field = 0;
    let mut pow: Field = 1;
    for i in 0..KEY_BITS {
        let mut count: u32 = 0;
        for j in 0..R {
            let x = sketch[i * R + j] ^ template[i * R + j];
            count += x as u32;
        }
        let bit = (count > (R / 2)) as u32;
        key_field += pow * (bit as Field);
        pow *= 2;
    }
    let commit = std::hash::pedersen_hash([key_field]);
    let mut chunks: [Field; NCHUNK] = [0; NCHUNK];
    for c in 0..NCHUNK {
        let mut acc: Field = 0;
        let mut cpow: Field = 1;
        for j in 0..PACK {
            acc += cpow * (sketch[c * PACK + j] as Field);
            cpow *= 2;
        }
        chunks[c] = acc;
    }
    let sketch_hash = std::hash::pedersen_hash(chunks);
    std::hash::pedersen_hash([commit, sketch_hash])
}
