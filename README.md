# signbridge

signbridge is an internal release attestation gateway. It handles tag event webhooks from the source platform,
validates mutation policy, issues attestation receipts into a transparency log, and promotes artifacts to the
downstream registry.
Inspired by CVE-2026-33634.

## install

pip install -e .[dev]

## run tests

pytest tests/
