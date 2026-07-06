// ZK-PRNU key recovery -- v2: anonymous registry membership.
//
// v1 proved: "my private bits decode with the public sketch to a key committing
// to X" and left comparing X to the registry to the verifier -- which links the
// proof to one device. v2 removes that link:
//
//   * the sketch moves to PRIVATE input, bound by a pedersen hash
//   * the device leaf = pedersen(key_commitment, sketch_hash)
//   * the circuit proves leaf MEMBERSHIP in a public registry root via a
//     private Merkle path -- verifier learns "some registered device", not which
//
// Public inputs shrink from 8064 sketch bits (258KB) to ONE field (the root).
//
// Statement:
//   exists fresh_bits, sketch, path :
//     key        = majority_decode(sketch XOR fresh_bits)      (r-repetition)
//     leaf       = H( H(key), H(pack(sketch)) )
//     merkle(leaf, path) == registry_root                       (public)

global KEY_BITS: u32 = 128;
global R: u32 = 63; // odd -> unambiguous majority
global N: u32 = 8064; // KEY_BITS * R
global DEPTH: u32 = 4; // demo registry: 16 devices (production: ~24-32)
global PACK: u32 = 224; // bits packed per field chunk
global NCHUNK: u32 = 36; // N / PACK

fn decode_key(fresh_bits: [bool; 8064], sketch: [bool; 8064]) -> Field {
    let mut key_field: Field = 0;
    let mut pow: Field = 1;
    for i in 0..KEY_BITS {
        let mut count: u32 = 0;
        for j in 0..R {
            let x = sketch[i * R + j] ^ fresh_bits[i * R + j];
            count += x as u32;
        }
        let bit = (count > (R / 2)) as u32;
        key_field += pow * (bit as Field);
        pow *= 2;
    }
    key_field
}

fn pack_sketch(sketch: [bool; 8064]) -> [Field; 36] {
    let mut chunks: [Field; 36] = [0; 36];
    for c in 0..NCHUNK {
        let mut acc: Field = 0;
        let mut pow: Field = 1;
        for j in 0..PACK {
            acc += pow * (sketch[c * PACK + j] as Field);
            pow *= 2;
        }
        chunks[c] = acc;
    }
    chunks
}

fn device_leaf(fresh_bits: [bool; 8064], sketch: [bool; 8064]) -> Field {
    let key = decode_key(fresh_bits, sketch);
    let commit = std::hash::pedersen_hash([key]);
    let sketch_hash = std::hash::pedersen_hash(pack_sketch(sketch));
    std::hash::pedersen_hash([commit, sketch_hash])
}

fn merkle_root(leaf: Field, siblings: [Field; 4], index_bits: [bool; 4]) -> Field {
    let mut node = leaf;
    for i in 0..DEPTH {
        let (l, r) = if index_bits[i] {
            (siblings[i], node)
        } else {
            (node, siblings[i])
        };
        node = std::hash::pedersen_hash([l, r]);
    }
    node
}

fn main(
    fresh_bits: [bool; 8064], // private: fingerprint from this capture
    sketch: [bool; 8064], // private: helper data (bound via hash into leaf)
    siblings: [Field; 4], // private: Merkle path
    index_bits: [bool; 4], // private: path directions (hides WHICH device)
    registry_root: pub Field, // public: the device registry
) {
    let leaf = device_leaf(fresh_bits, sketch);
    assert(merkle_root(leaf, siblings, index_bits) == registry_root);
}

// ---------------------------------------------------------------------------

fn test_fixture() -> ([bool; 8064], [bool; 8064]) {
    // deterministic enroll bits + sketch for key = alternating 1,0,1,0...
    let mut enroll: [bool; 8064] = [false; 8064];
    for i in 0..N {
        enroll[i] = (i * 7 + 3) % 5 < 2;
    }
    let mut sketch: [bool; 8064] = [false; 8064];
    for i in 0..KEY_BITS {
        let kb = (i % 2) == 0;
        for j in 0..R {
            sketch[i * R + j] = kb ^ enroll[i * R + j];
        }
    }
    (enroll, sketch)
}

#[test]
fn test_membership_with_noise() {
    let (enroll, sketch) = test_fixture();

    // fresh capture: 9 flips per block (< 31 -> correctable)
    let mut fresh: [bool; 8064] = enroll;
    for i in 0..KEY_BITS {
        for j in 0..9 {
            let idx = i * R + (j * 5);
            fresh[idx] = !fresh[idx];
        }
    }

    // registry: our device at index 5 of a 16-leaf tree, dummy leaves elsewhere
    let leaf = device_leaf(enroll, sketch);
    let mut leaves: [Field; 16] = [0; 16];
    for i in 0..16 {
        leaves[i] = (i as Field) + 1000; // dummy devices
    }
    leaves[5] = leaf;

    // build the tree
    let mut l1: [Field; 8] = [0; 8];
    for i in 0..8 {
        l1[i] = std::hash::pedersen_hash([leaves[2 * i], leaves[2 * i + 1]]);
    }
    let mut l2: [Field; 4] = [0; 4];
    for i in 0..4 {
        l2[i] = std::hash::pedersen_hash([l1[2 * i], l1[2 * i + 1]]);
    }
    let mut l3: [Field; 2] = [0; 2];
    for i in 0..2 {
        l3[i] = std::hash::pedersen_hash([l2[2 * i], l2[2 * i + 1]]);
    }
    let root = std::hash::pedersen_hash([l3[0], l3[1]]);

    // path for index 5 (binary 0101, LSB-first directions): sibling leaf 4,
    // then l1[3], l2[0], l3[1]
    let siblings: [Field; 4] = [leaves[4], l1[3], l2[0], l3[1]];
    let index_bits: [bool; 4] = [true, false, true, false]; // 5 = 0b0101 LSB-first

    // genuine fresh capture proves membership
    main(fresh, sketch, siblings, index_bits, root);

    // impostor bits decode to a different key -> different leaf -> root mismatch
    let mut impostor: [bool; 8064] = enroll;
    for j in 0..40 {
        impostor[j] = !impostor[j]; // 40 flips in block 0 (> 31 -> key bit flips)
    }
    let bad_leaf = device_leaf(impostor, sketch);
    assert(bad_leaf != leaf);
    assert(merkle_root(bad_leaf, siblings, index_bits) != root);
}
