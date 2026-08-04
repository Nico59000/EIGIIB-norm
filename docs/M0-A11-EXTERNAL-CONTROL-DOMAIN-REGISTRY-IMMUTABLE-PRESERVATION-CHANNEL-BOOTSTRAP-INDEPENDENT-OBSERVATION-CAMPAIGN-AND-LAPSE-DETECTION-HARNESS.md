# M0-A11 — External Control-Domain Registry, Immutable Preservation Channel Bootstrap, Independent Observation Campaign and Lapse-Detection Harness

## 1. Purpose

M0-A11 establishes the complete preparatory contract needed to acquire the external evidence missing after M0-A10. It does not select a provider, create an account, provision storage, bind an independent observer, start a campaign or adopt E17.

Its result is:

`external-evidence-acquisition-prepared-not-activated`.

## 2. Exact source boundary

M0-A11 consumes M0-A10 at exact head `2891265f04a5d9a4d69c134fa48881b0ed93fe13` and preserves the exact stable E16 bundle identity:

- object: `eigiib-e16-1.0-stable-bundle.tar.gz`;
- bytes: `985664`;
- SHA-256: `96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde`.

M0-A10 established bounded publication and readback through GitHub Release and GHCR. Those routes remain one existing provider domain and cannot be counted as external preservation independence.

## 3. Claim algebra

The following implications are denied:

- provider name ⇒ independent control domain;
- declared retention ⇒ enforced immutability;
- configured schedule ⇒ completed observation;
- two endpoints ⇒ two failure domains;
- different regions ⇒ different identity or billing authority;
- external service ⇒ independent observer;
- empty lapse ledger ⇒ successful preservation history.

Unknown external facts are negative for admission. They are not silently inferred.

## 4. Control-domain registry

The registry separates control into nine dimensions:

1. provider operator;
2. tenant account;
3. identity root;
4. privileged administrator;
5. billing authority;
6. credential store;
7. execution plane;
8. region or failure domain;
9. audit-log custody.

M0-A11 records four roles:

- the existing GitHub publication domain;
- a primary external preservation placeholder;
- a secondary external preservation placeholder;
- an independent-observer placeholder.

The three future external roles remain `unbound`. Their control dimensions are explicitly `unbound`, and no independence result can be produced until signed attestations and evidence references are supplied and independently checked.

## 5. Immutable-channel bootstrap

Two channel contracts target the exact M0-A10 bundle. Each contract requires:

- an external control-domain binding;
- a provider resource identity and object-version identity;
- compliance lock or an equivalent non-bypassable retention mechanism;
- retention-policy readback;
- authorized and privileged deletion-denial evidence;
- audit-log export;
- exact object readback.

Both channels remain `planned-not-provisioned`. Endpoint, resource ID, object version, retention window and retain-until time remain `unbound`. An empty evidence array is mandatory in this slice.

## 6. Independent observation campaign

The campaign contract is deterministic and initially inactive.

- cadence: 86,400 seconds;
- grace: 21,600 seconds;
- lapse threshold: 172,800 seconds after the expected due time;
- time base: UTC RFC 3339;
- sequence origin: 1;
- digest algorithm: SHA-256;
- chain: contiguous sequence and previous-observation digest;
- expected channels: both external immutable channels;
- observer: the independent-observer control domain.

Activation requires a bound observer, two provisioned locked channels, a bound observer signing key, recorded initial object versions and an approved campaign anchor.

## 7. Lapse state machine

For an active campaign, the deterministic evaluator returns exactly one state:

- `awaiting-first-observation` before the first due time;
- `current` at or before the next due time;
- `grace` after due time and within the grace interval;
- `overdue` after grace and before the lapse threshold;
- `lapsed` after the lapse threshold;
- `invalid` for malformed sequence, time, digest, channel set or activation state.

Before activation, the only admitted state is `not-activated`. Any observation in a non-activated ledger is invalid.

## 8. Observation envelope

Every future observation must bind:

- campaign identity;
- contiguous sequence;
- UTC observation time;
- previous observation digest;
- observer-domain identity and key identity;
- exact results for both channel identities;
- its own canonical SHA-256 digest.

The envelope schema does not itself establish signature trust. M0-A12 must bind the observer key, signature verification route and external attestation.

## 9. Promotion gates

M0-A12 is classified `ready-for-external-activation-only` after this preparatory slice. It still requires real evidence:

- two bound external control-domain attestations;
- two provisioned immutable channels;
- one bound independent observer;
- one valid signed observation per channel;
- one complete control-dimension diversity evaluation.

E17 remains `not-ready-for-adoption`. Long-horizon evidence, correlated-failure evidence, multi-authority deletion/quarantine/hold evidence and an independent live matrix remain absent.

## 10. Security and privacy boundary

M0-A11 contains no secrets. Future attestations must use stable pseudonymous identifiers where possible and must never commit access tokens, private keys, recovery codes, full billing records or unnecessary personal data. Evidence references may identify external records without embedding their confidential contents.

## 11. Explicit nonclaims

M0-A11 does not establish any selected provider, created account, external authority, provisioned channel, retention lock, legal hold, deletion prevention, independent observer, signed observation, long-horizon preservation, provider independence, correlated-failure resistance or E17 adoption.
