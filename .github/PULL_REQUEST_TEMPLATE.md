## Summary

<!-- One or two sentences on what this PR changes and why. -->

## Changes

- ...

## Test plan

- [ ] Formatting and Clippy checks pass for the native candidate
- [ ] The manually dispatched native CI batch passes for this exact commit on Windows, Linux and both macOS architectures
- [ ] Required assertion mappings and native execution receipts are complete
- [ ] Affected commands were practically tested; untested paths and blockers are stated
- [ ] Documentation matches the change; signed artifacts and replacement checks are supplied if this PR performs cutover

Do not treat retained Python checks or the current root `Run.ps1` as native
verification. See [Contributing](../CONTRIBUTING.md) for bounded checks and
migration gates.

## Related issues

Closes #
