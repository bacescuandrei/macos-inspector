## Purpose

Describe the problem and the reason for this change.

## Validation

List the tests and manual checks you ran.

## Safety review

- [ ] Collection remains read-only.
- [ ] No command uses a shell or requests elevated privileges.
- [ ] New evidence is bounded and does not expose secrets in logs or reports.
- [ ] Network access, if any, is explicit and documented.
- [ ] Tests cover parsing, failure states, and unavailable data.
