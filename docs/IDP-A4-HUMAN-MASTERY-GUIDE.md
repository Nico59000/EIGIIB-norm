# IDP-A4 human mastery guide

Use IDP-A4 when the public should be able to observe project state without receiving the restricted subject itself.

The important separation is:

`restricted subject -> private opening material -> salted commitment -> D0 announcement`

Only the final announcement crosses the public boundary. The internal artifact identifier, exact D3/D4 class, payload digest and salt do not.

A commitment is not a public proof of the hidden payload unless opening material is later disclosed under a separate policy. Likewise, seeing no A4 announcement is not evidence that no restricted subject exists.

For withdrawal, never remove the previous announcement. Keep the record, set its state to `withdrawn`, retain its commitment, and append exactly one public withdrawal event. This preserves public history without opening the restricted subject.

The anti-correlation checks in A4 are deliberately bounded. They detect reuse of handles, salts and commitments and prevent obvious internal-field leakage. They do not prove that production random generation has sufficient entropy and do not prevent correlation from timing, traffic, wording, external events or other metadata.

All committed private witnesses in the conformance corpus are synthetic. They must never be interpreted as an inventory of real restricted project material.
