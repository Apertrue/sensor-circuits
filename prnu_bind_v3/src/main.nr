// v3: per-photo THRESHOLD BINDING (Tier 2) -- packed-field ABI.
//
// Proves: "the residual bits of THIS ordinary photo agree with a registered
// device's enrolled bits beyond chance" -- one photo, no key recovery.
//
//   bits arrive packed 224-per-field (ABI: 2x146 fields, not 2x32,704 bools);
//   in-circuit to_le_bits recovers them. The binding leaf hashes the packed
//   enrolled chunks directly.
//
//   mismatches = popcount(fresh XOR enrolled) < TAU
//   pedersen(enrolled_chunks) = leaf, member of public registry root
//
// Frozen params (SPEC_FROZEN 5): N = 146*224 = 32,704 bits; TAU = 15534 =
// 0.475*N. The worst real scene frame sits ~6.8 effective-sigma over the
// impostor mean (paperA measures a per-photo impostor BER sigma of 0.0037, so
// effective N ~ 18,300 -- bits are not independent). We report the empirical
// result, zero false accepts in 308 cross-camera trials (FA bounded below 1%
// at 95% CI), not an independence-based tail probability.

global TAU: u32 = 15534; // 0.475 * N (N = 32,704) -- SPEC_FROZEN 5 production value
global PACK: u32 = 224;
global NCHUNK: u32 = 146;
global DEPTH: u32 = 4;

fn main(
    fresh: [Field; 146], // private: this photo's residual bits, packed
    enrolled: [Field; 146], // private: device reference bits, packed
    siblings: [Field; 4], // private: Merkle path
    index_bits: [bool; 4], // private: which device (hidden)
    registry_root: pub Field,
) {
    let mut mismatch: Field = 0;
    for c in 0..NCHUNK {
        let fb: [bool; 224] = fresh[c].to_le_bits();
        let eb: [bool; 224] = enrolled[c].to_le_bits();
        for j in 0..PACK {
            mismatch += (fb[j] ^ eb[j]) as Field;
        }
    }
    assert((mismatch as u32) < TAU);

    let mut node = std::hash::pedersen_hash(enrolled);
    for i in 0..DEPTH {
        let (l, r) = if index_bits[i] {
            (siblings[i], node)
        } else {
            (node, siblings[i])
        };
        node = std::hash::pedersen_hash([l, r]);
    }
    assert(node == registry_root);
}
