# Deployment examples and operator contract

The files in this directory are examples, not universal production
configurations or a promise that an installed deployment is secure. Automated
tests cover only the versions and files at the repository commit being tested.

The operator is responsible for selecting and adapting the actual proxy and
service configuration, keeping every component and transitive dependency
patched, monitoring security advisories, validating the installed files after
each change, and testing the complete path through Tor, the proxy, and Axum.
The operator also owns resource limits, file permissions, journal retention,
encrypted off-host backups, and recurring restore drills.

Whatever tooling is selected must preserve the security contract documented in
the root README and `docs/DEPLOYMENT.md`: one application instance, a loopback
Axum listener, no direct public exposure, bounded request parsing, the standard
`429`/`503` behavior, and one shared rate-limited cache representation for
`/attempts`.

The nginx example has a static regression guard and an executable CI smoke
test. Those checks cover the committed include against the current CI runner
package; they do not replace validation of the operator's installed version,
configuration, service, filesystem, or Tor path.
