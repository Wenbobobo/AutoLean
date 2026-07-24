# Review Packets

Review packets are immutable once a decision is recorded. A correction creates
a new packet and, when semantics change, a new Builder-owned contract revision.
Each packet references the source-preparation record, the frozen contract hash,
the exact proof boundary, and the verifier evidence artifact without copying
restricted source material or raw execution logs.
