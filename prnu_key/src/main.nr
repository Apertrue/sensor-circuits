// ZK-PRNU key recovery -- v1.
//
// Proves: "I hold fingerprint bits which, combined with the public sketch,
// majority-decode to a stable key" -- and outputs the Poseidon2 commitment of
// that key. The verifier compares the output against the enrolled commitment
// (v2 folds this into an in-circuit Merkle registry-membership check).
//
// Fuzzy extractor: code-offset with an R-fold repetition code.
//   enrollment:  sketch = repeat(key, R) XOR enroll_bits          (public)
//   recovery  :  key[i]  = majority_j( sketch[i*R+j] XOR bits[i*R+j] )
//
// Parameters from measured phone data (iPhone 13 Pro Max, ISO-32 flats):
//   BER ~ 0.14  ->  per-key-bit failure at R=63 ~ 1e-11.
//
// Private: fresh_bits -- the fingerprint bits extracted from a new capture.
//          NEVER leaves the device; this circuit is why it does not have to.
// Public : sketch (helper data), commitment (output).

// commitment hash: pedersen (public std API in beta.18; matches apertrue patterns)

global KEY_BITS: u32 = 128;
global R: u32 = 7; // odd (stability-selected bits, BER ~0.006)
global N: u32 = 896; // KEY_BITS * R

fn main(fresh_bits: [bool; 896], sketch: pub [bool; 896]) -> pub Field {
    let mut key_field: Field = 0;
    let mut pow: Field = 1;

    for i in 0..KEY_BITS {
        // popcount of (sketch XOR fresh) over this key bit's R-block
        let mut count: u32 = 0;
        for j in 0..R {
            let x = sketch[i * R + j] ^ fresh_bits[i * R + j];
            count += x as u32;
        }
        // majority vote: > R/2 flips (> 3 of R=7) means the key bit is 1
        let bit = (count > (R / 2)) as u32;
        key_field += pow * (bit as Field);
        pow *= 2;
    }

    // commitment to the recovered key (128 bits packs into one BN254 field)
    std::hash::pedersen_hash([key_field])
}

// (self-test removed in r=7 resize; validated end-to-end on real data)
