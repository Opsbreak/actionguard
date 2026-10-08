# Security policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in actionguard -- for example a
way to make it crash or hang on crafted input, to execute code while scanning, to make
`actionguard pin` write something other than the resolved commit, or a detection bypass
that undermines its core guarantees -- please report it privately. **Do not open a public
issue.**

Use either channel:

- **GitHub private vulnerability reporting:** on
  [github.com/Opsbreak/actionguard](https://github.com/Opsbreak/actionguard), go to
  *Security* -> *Report a vulnerability*.
- **Email:** [admin@opsbreak.com](mailto:admin@opsbreak.com).

Please include the affected version or commit, a description of the issue and its impact,
and a minimal reproducing workflow or input file if possible.

## What to expect

- We acknowledge reports within **3 business days**.
- We will confirm the issue, keep you informed of progress, and agree on a disclosure
  timeline with you. We follow **coordinated disclosure**: details are published once a
  fix is available, or after a mutually agreed deadline.
- With your permission, we credit reporters in the release notes and advisory.

## Scope

In scope: the code in this repository (the `actionguard` Python package, its CLI and the
repository's own CI configuration).

Out of scope: vulnerabilities in workflows that actionguard *reports on* (report those to
the affected project), and the intentionally vulnerable workflows under
`examples/vulnerable-repo/`, which exist as test inputs and are never executed.

False negatives (a vulnerable pattern actionguard misses) are welcome as regular issues
unless the details would put a specific third-party project at risk -- in that case,
please use the private channels above.

## Supported versions

Security fixes are made on the latest release.
