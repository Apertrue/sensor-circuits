// Enrollment-side: binding leaf + demo root/path (index 5 of 16), packed ABI.

global DEPTH: u32 = 4;

fn main(enrolled: [Field; 146]) -> pub [Field; 6] {
    let leaf = std::hash::pedersen_hash(enrolled);
    let mut leaves: [Field; 16] = [0; 16];
    for i in 0..16 {
        leaves[i] = (i as Field) + 2000;
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
