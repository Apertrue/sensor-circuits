// Enrollment-side helper: computes the device leaf, demo registry root and
// Merkle path (device at index 5 of 16, dummy leaves elsewhere).
// Output: [leaf, root, sib0, sib1, sib2, sib3]

global KEY_BITS: u32 = 128;
global R: u32 = 7;
global N: u32 = 896;
global PACK: u32 = 224;
global NCHUNK: u32 = 4;

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

fn main(fresh_bits: [bool; 896], sketch: [bool; 896]) -> pub [Field; 6] {
    let key = decode_key(fresh_bits, sketch);
    let commit = std::hash::pedersen_hash([key]);
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
    let sketch_hash = std::hash::pedersen_hash(chunks);
    let leaf = std::hash::pedersen_hash([commit, sketch_hash]);

    let mut leaves: [Field; 16] = [0; 16];
    for i in 0..16 {
        leaves[i] = (i as Field) + 1000;
    }
    leaves[5] = leaf;
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
    [leaf, root, leaves[4], l1[3], l2[0], l3[1]]
}
