# Thesis attack lab extension

This extension exposes isolated teaching simulations for SQL injection, RCE,
authentication bypass, path traversal, and IDOR. It never queries production
tables, issues a real CFMS token, starts a process, or reads a host path.

Every vulnerability action requires both `LAB_MODE=true` and its matching
`CFMS_VULN_*_ENABLED=true` flag at server startup. With the default environment
the extension registers no actions or capability flags.

Actions:

- `lab_sqli`: allowlisted payloads over the in-memory `LAB_USERS` fixture.
- `lab_rce`: fixed-command simulation; no shell or subprocess is used.
- `lab_auth_bypass`: returns an explicitly unusable token for LAB accounts only.
- `lab_path_traversal`: resolves allowlisted probes inside a virtual filesystem.
- `lab_idor`: requires normal Core authentication, then skips ownership only
  for isolated LAB objects; production objects are never queried or returned.
- `reset_lab`, `lab_status`, and `lab_chain_step`: reset and drive the two
  ordered attack demonstrations (`identity_takeover` and `sandbox_breach`).

Honeytoken hits are retained in a bounded in-memory alert list and published on
the provider event-bus channel `cfms.lab.honeytoken`. Profile examples live in
`profiles/`. `baseline` deliberately keeps Core lab vulnerabilities enabled so
the security gateway can demonstrate blocking; `hardened` disables the lab at
Core as defense in depth.
