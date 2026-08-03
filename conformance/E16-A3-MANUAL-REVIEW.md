# E16-A3 Manual Review Gate

A reviewer MUST confirm all of the following before treating an E16-A3 decision as operationally usable:

- the exact E16-A2 source commit and authority freeze are available;
- the source placement decision is positive and content-identical;
- the window boundaries and clock-basis declaration are intentional;
- opening and closing observations bind the exact declared boundaries;
- observation evidence is bounded and is not described as continuous retention proof;
- reader and custodian have distinct declared identities and control domains;
- restore executor and verifier have distinct declared identities and control domains;
- readback, restore and verification content identities agree exactly;
- negative evidence retains precedence;
- no claim of trusted time, actual independence, future durability or future restorability is inferred.

A reviewer MUST reject a decision whose stored gates differ from the checker-derived gates.
