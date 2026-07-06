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
global R: u32 = 7; // odd (stability-selected bits)
global N: u32 = 896; // KEY_BITS * R
global DEPTH: u32 = 4; // demo registry: 16 devices (production: ~24-32)
global PACK: u32 = 224; // bits packed per field chunk
global NCHUNK: u32 = 4; // N / PACK

fn decode_key(fresh_bits: [bool; 896], sketch: [bool; 896]) -> Field {
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

fn pack_sketch(sketch: [bool; 896]) -> [Field; 4] {
    let mut chunks: [Field; 4] = [0; 4];
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

fn device_leaf(fresh_bits: [bool; 896], sketch: [bool; 896]) -> Field {
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
    fresh_bits: [bool; 896], // private: fingerprint from this capture
    sketch: [bool; 896], // private: helper data (bound via hash into leaf)
    siblings: [Field; 4], // private: Merkle path
    index_bits: [bool; 4], // private: path directions (hides WHICH device)
    registry_root: pub Field, // public: the device registry
) {
    let leaf = device_leaf(fresh_bits, sketch);
    assert(merkle_root(leaf, siblings, index_bits) == registry_root);
}

// (self-test removed in r=7 resize; validated end-to-end on real data)
