# sensor-circuits

Zero-knowledge circuits for **sensor-based photo provenance**: proving a photo
came from a specific physical camera sensor without revealing the sensor
fingerprint. Provenance is grounded in the sensor's physical PRNU fingerprint
rather than a signed manifest.

Written in [Noir](https://noir-lang.org), proven with barretenberg UltraHonk.
Gate counts and prove times below are from the reference platforms noted in each
commit.

## Circuits

| Package | Proves | ~gates |
|---|---|---|
| `prnu_bind_v3` | this photo's PRNU bits agree with a registered camera beyond chance (per-photo threshold tier) | ~170k |
| `prnu_key`, `prnu_key_v2` | fuzzy-extract a stable key from stability-selected PRNU bits | 14k / 28.7k |
| `cancelable_enroll` | enrolment consistency over a keyed, revocable BioHash template | 267k |
| `enrollment_nullifier` | one-time registration tag (verbatim-duplicate refusal) | 29k |
| `zk_attest`, `zk_attest_delegate` | Apple App Attest verified in-circuit; per-capture hardware anchor with zero Apple calls | 321k / 415k |
| `capture_aggregator` | one recursive proof over the hardware anchor + sensor membership | — |
| `registry_helper`, `v3_registry_helper` | enrolment-side Merkle leaf/root helpers | — |
| `rec_spike_inner`, `rec_spike_outer` | recursive aggregation helpers | — |

Registration and matching run over **cancelable templates**: the raw fingerprint
is never registered or published, and a leaked template is retired by rotating a
device-held key.

## Build

Each package is a standard Nargo project:

```sh
cd prnu_bind_v3
nargo check
nargo compile
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE). The vendored elliptic-curve code under
`zk_attest*/src/crypto/noir_bigcurve_vendor/` is third-party under MIT; see the
`VENDORED_FROM.md` beside it for provenance.
