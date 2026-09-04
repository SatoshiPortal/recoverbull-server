# RecoverBull nginx deployment example

This is a CI-tested example, not a universal production configuration or a
security guarantee for an installed deployment. The operator owns adaptation,
package security updates, advisory monitoring, installed-config validation,
and end-to-end testing. See [`deploy/README.md`](../README.md) for the common
contract.

`recoverbull.conf` is an `http`-context include for one nginx instance on
`127.0.0.1:3000`. Install it at the distribution-specific include path, make
sure no other proxy owns that listener, and keep Axum private on
`127.0.0.1:3001`. The cache directory and error log are operator-owned: create
them with permissions appropriate to the installed nginx identity and apply
the retention policy in `docs/RETENTION.md`.

The example intentionally provides:

* one Host/query-independent GET cache key for `/attempts`;
* a 35-second cache lock timeout and age, covering a cold Axum build;
* a GET-only global edge bucket (Tor clients share one source address);
* JSON `503` plus `Retry-After` for nginx-generated pressure, without
  intercepting Axum's targeted `429` or shared-pressure response;
* unbuffered request bodies, so Axum's 30-second timeout bounds their total
  lifetime instead of nginx applying only an inactivity timeout;
* loopback listeners/upstreams, bounded headers and bodies, no access log, and
  explicit connection and response-rate limits.

Before admitting onion traffic, record `nginx -V`, review its configure flags
and package security status, run `sudo nginx -t`, and execute:

```sh
python3 deploy/nginx/smoke.py /usr/sbin/nginx
```

The smoke renders the include into a private temporary nginx configuration and
tests syntax, request-body streaming, cache single-flight, Host/query
normalization, conditional 304, method scoping, body size, upstream status
preservation, and edge pressure. It does not test the operator's installed
include, Tor path, filesystem ownership, systemd unit, kernel limits, or log
retention; repeat equivalent checks against the installed service.
