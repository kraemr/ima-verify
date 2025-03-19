# README

This was made to be able to verify a given IMA-Event Log with a PCR-Aggregate Digest.
The Code was heavily inspired by linux-test-project.

I mostly made this as a part of my bachelor thesis project involving remote attestation.

Currently this is VERY flimsy and will only work with ima-ng templates and sha1,sha256 Hashes for IMA-EventLog.
Also the Bios Log reading doesnt work properly.


# TODO
- add Tool to create/verify quotes
- add Testcases
- Correctly read ALL Bios logs
- What should be done if bios log isnt written ???
- What should be done if TPM registers for sha1 is written but we have only sha256 logs ...
- support all ima-templates
