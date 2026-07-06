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
global R: u32 = 63; // odd -> unambiguous majority
global N: u32 = 8064; // KEY_BITS * R

fn main(fresh_bits: [bool; 8064], sketch: pub [bool; 8064]) -> pub Field {
    let mut key_field: Field = 0;
    let mut pow: Field = 1;

    for i in 0..KEY_BITS {
        // popcount of (sketch XOR fresh) over this key bit's R-block
        let mut count: u32 = 0;
        for j in 0..R {
            let x = sketch[i * R + j] ^ fresh_bits[i * R + j];
            count += x as u32;
        }
        // majority vote: >31 of 63 flips means the key bit is 1
        let bit = (count > (R / 2)) as u32;
        key_field += pow * (bit as Field);
        pow *= 2;
    }

    // commitment to the recovered key (128 bits packs into one BN254 field)
    std::hash::pedersen_hash([key_field])
}

#[test]
fn test_roundtrip_small_noise() {
    // synthetic: key=all-ones pattern via sketch=enroll_bits XOR repeat(key),
    // then flip a few bits (< R/2 per block) and expect identical commitment.
    let mut enroll: [bool; 8064] = [false; 8064];
    // arbitrary deterministic enroll bits
    for i in 0..N {
        enroll[i] = (i * 7 + 3) % 5 < 2;
    }
    // key bits: alternating 1,0,1,0...
    let mut sketch: [bool; 8064] = [false; 8064];
    for i in 0..KEY_BITS {
        let kb = (i % 2) == 0;
        for j in 0..R {
            sketch[i * R + j] = kb ^ enroll[i * R + j];
        }
    }
    let c_enroll = main(enroll, sketch);

    // fresh capture: flip 9 bits inside each block (9 < 31 -> correctable)
    let mut fresh: [bool; 8064] = enroll;
    for i in 0..KEY_BITS {
        for j in 0..9 {
            let idx = i * R + (j * 5); // spread flips
            fresh[idx] = !fresh[idx];
        }
    }
    let c_fresh = main(fresh, sketch);
    assert(c_enroll == c_fresh);

    // sanity: too many flips (>= 32 in a block) must change the key
    let mut broken: [bool; 8064] = enroll;
    for j in 0..32 {
        broken[j] = !broken[j]; // 32 flips in block 0
    }
    let c_broken = main(broken, sketch);
    assert(c_broken != c_enroll);
}
