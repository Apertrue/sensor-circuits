// v3: per-photo THRESHOLD BINDING (Tier 2) -- packed-field ABI.
//
// Proves: "the residual bits of THIS ordinary photo agree with a registered
// device's enrolled bits beyond chance" -- one photo, no key recovery.
//
//   bits arrive packed 224-per-field (ABI: 2x1170 fields, not 2x262k bools);
//   in-circuit to_le_bits recovers them. The binding leaf hashes the packed
//   enrolled chunks directly.
//
//   mismatches = popcount(fresh XOR enrolled) < TAU
//   pedersen(enrolled_chunks) = leaf, member of public registry root
//
// Measured params (July 2026): N=262,080; worst scene frame BER 0.494 ~ 6 sigma;
// TAU = 0.4965*N = 130,122. At this N impostor FA ~ 2e-4 -- production target is
// N ~ 1M for FA ~ 1e-12 (same design, bigger loop).

global TAU: u32 = 16265;
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
