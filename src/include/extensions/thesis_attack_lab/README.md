# Thesis attack lab extension

This extension exposes isolated teaching simulations for SQL injection, RCE,
authentication bypass, path traversal, and IDOR. The simulated vulnerability
actions never query production documents, issue a real CFMS token, start a
process, or read a host path.

Every vulnerability action requires `LAB_MODE=true`. This is a startup-only
deployment gate: when it is false, the extension registers no actions or
capability flags. In an isolated LAB deployment, a `sysop` can then turn each
allowlisted simulation on or off at runtime with `lab_set_vulnerability`; no
Core restart is required.

Actions:

- `lab_sqli`: allowlisted payloads over the in-memory `LAB_USERS` fixture.
- `lab_rce`: fixed-command simulation; no shell or subprocess is used.
- `lab_auth_bypass`: returns an explicitly unusable token for LAB accounts only.
- `lab_path_traversal`: resolves allowlisted probes inside a virtual filesystem.
- `lab_idor`: requires normal Core authentication, then skips ownership only
  for isolated LAB objects; production objects are never queried or returned.
- `reset_lab`, `lab_status`, and `lab_chain_step`: reset and drive ordered
  demonstrations (`identity_takeover`, `sandbox_breach`, and custom chains).
- `lab_configure_chain`: a `sysop` may publish a `custom-*` chain of one to
  five unique allowlisted exercises. All features required by the chain must
  already be enabled, and each step requires the evidence returned by the
  previous step.

Honeytoken hits are retained in a bounded in-memory alert list and published on
the provider event-bus channel `cfms.lab.honeytoken`. Profile examples live in
`profiles/`. `baseline` deliberately keeps Core lab vulnerabilities enabled so
the security gateway can demonstrate blocking; `hardened` disables the lab at
Core as defense in depth.

Runtime switch values and custom chains are intentionally process-local: a Core
restart returns to the deployment profile and clears custom chains. This keeps
teaching state out of production business data.
