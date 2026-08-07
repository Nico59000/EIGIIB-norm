# IDP-A2 Human Mastery Guide

IDP-A2 answers one question: **when a bridge is permitted by A1, which exact identity and transport context is allowed to instantiate it?**

The safe mental model is:

```text
L0 authority
  != bridge principal
  != endpoint
  != transport
  != pin
```

A2 binds all five without collapsing them.

The current registry is deliberately synthetic and structural. Its fingerprints and pins are test values. Its endpoints have no locator. This is a positive property: no production endpoint is inferred before it exists.

When the local Git root is deployed, promotion to an operational A2 registry must replace synthetic authenticators and pinsets with independently observed real values and bind exact endpoint locators. Do not edit a structural object in place and call it operational; create an auditable successor state.

The anti-confusion replay must continue to reject:

- root-role impersonation;
- outbound/inbound role reversal;
- endpoint substitution;
- transport substitution;
- pin substitution;
- D5 transport;
- reuse of one route identity as another route identity.

A successful A2 replay proves only route-context conformance. Audience eligibility and quarantine promotion belong to A3.
