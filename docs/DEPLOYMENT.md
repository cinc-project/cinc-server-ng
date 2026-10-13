# Deploying cinc-server-ng: TLS and load balancers

This covers running the standalone binary where real clients reach it over
HTTPS: serving TLS directly, putting it behind a reverse proxy or load
balancer, and stopping it without dropping requests.

## Topologies

| topology | TLS terminates at | cinc-server-ng flags |
|---|---|---|
| Direct | cinc-server-ng | `--tls-cert`, `--tls-key` |
| Reverse proxy / L7 load balancer (nginx, Caddy, HAProxy, AWS ALB, GCP HTTPS LB) | the proxy | none required; `--external-url` if the proxy rewrites `Host` |
| L7 load balancer, re-encrypting to the backend | the proxy, then again at cinc-server-ng | `--tls-cert`, `--tls-key`, and as above |
| L4 / TCP passthrough (AWS NLB, HAProxy `mode tcp`) | cinc-server-ng | `--tls-cert`, `--tls-key` |

### Run one active instance

Put **one** active cinc-server-ng behind a load balancer, never several. State
lives in the process (the memory backend) or in a local SQLite file, and the
search index and group-membership index are built in memory and updated as
that process writes. A second instance, even one opened on the same SQLite
file, would not see the first one's writes in its search results or
authorization decisions. Use the load balancer for TLS, a stable address,
health checking and draining. For high availability, run active/passive: a
standby that the load balancer only sends traffic to once the primary fails its
health check, with the SQLite file on storage the standby can take over.

## Serving TLS directly

```sh
cinc-server-ng --addr 0.0.0.0:443 \
  --tls-cert /etc/cinc/server.crt --tls-key /etc/cinc/server.key \
  --storage sqlite --db /var/lib/cinc/cinc.db
```

- `--tls-cert` is a PEM certificate, optionally followed by its intermediates
  (a full chain, as ACME clients write it). `--tls-key` is the matching PEM
  private key (RSA, ECDSA or Ed25519). Set both or neither.
- Both are read at startup, so a missing or mismatched pair fails immediately,
  not at a client's first handshake.
- TLS 1.2 is the minimum version. HTTP/2 is negotiated automatically for
  clients that offer it.
- Plain HTTP sent to the TLS port gets a `400`. There is no HTTP-to-HTTPS
  redirect: Chef clients are configured with a `chef_server_url`, not
  redirected to one.
- In containers, `CINC_SERVER_NG_TLS_CERT` and `CINC_SERVER_NG_TLS_KEY` set the
  same options.

**Renewing the certificate.** Replace the files, then send the process
`SIGHUP`. Connections opened after that get the new certificate; existing ones
keep the old one until they close. If the new files cannot be loaded (for
example a renewal caught half-written), the error is logged and the previous
certificate stays in service. This matters most on the memory backend, where a
restart loses all state. A certbot deploy hook:

```sh
certbot renew --deploy-hook 'pkill -HUP -x cinc-server-ng'
```

On Kubernetes, a mounted Secret is updated in place but nothing sends a
signal; use a reloader sidecar that signals the process (with
`shareProcessNamespace: true`), or terminate TLS at the ingress instead.

**Clients.** Point `chef_server_url` at `https://`. For a certificate from a
private CA, put the CA certificate in the client's `trusted_certs` directory,
or fetch the server's chain with `knife ssl fetch`, then check it with
`knife ssl check`.

## Behind a reverse proxy or load balancer

Four things matter here.

### 1. The returned URLs must name the public address

Chef responses contain absolute URLs: node and role URIs, search results,
sandbox URIs, and the pre-signed cookbook `file_store` URLs a chef-client
downloads cookbook files from. By default cinc-server-ng builds them from the
request, as Chef Infra Server does:

- the host comes from the `Host` header, so the proxy must pass the client's
  `Host` through unchanged;
- the scheme is `https` when the connection to cinc-server-ng is TLS, or when
  the proxy sends `X-Forwarded-Proto: https`. Only the values `http` and
  `https` are honoured, and in a chain of proxies the first entry wins.

When the proxy cannot do that (it rewrites `Host` to the backend's address,
or terminates TLS without sending `X-Forwarded-Proto`), set the public address
explicitly. This corresponds to erchef's `base_resource_url`:

```sh
cinc-server-ng --external-url https://chef.example.com
```

It must be `scheme://host[:port]` only. A path such as
`https://example.com/chef` is refused (see point 2 for why).

### 2. Don't change the request path or body

Every request is signed with Mixlib::Authentication, and the signature
covers the HTTP method, the **path**, a hash of the **body**, the timestamp
and the user ID. It does not cover the host, scheme or port, so terminating TLS
and changing the address are safe. A proxy that strips a path prefix
(`location /chef/ { proxy_pass http://backend/; }`) or modifies the body breaks
every signature. Serve the API at the root of its own host name.

The proxy must also forward the `X-Ops-*` request headers unmodified. Some
WAFs and API gateways strip unfamiliar headers. Requests are rejected once
their timestamp is more than 15 minutes from the server clock, so keep the
server's clock synchronized.

### 3. Health checks and draining

- Health check: `GET /_status`. No authentication. Returns `200` with
  `{"status":"pong",...}` when serving, and `503` with `{"status":"draining"}`
  while shutting down.
- `--shutdown-delay` (default `0`): on `SIGTERM` or `SIGINT`, the server first
  drains. `/_status` starts failing so the load balancer takes it out of
  rotation, every other request is still served, and each connection is closed
  after its current response so clients reconnect through the load balancer.
  Set it longer than the time your load balancer takes to mark a backend
  unhealthy (health-check interval × unhealthy threshold). A second signal
  skips the rest of the delay.
- `--shutdown-timeout` (default `30s`): after the delay, how long in-flight
  requests (for example a slow cookbook upload) get to finish before their
  connections are cut. If any are cut, the process exits non-zero.
- On Kubernetes, set `terminationGracePeriodSeconds` above
  `shutdown-delay + shutdown-timeout`, and use `/_status` as the readiness probe.

### 4. Timeouts and body sizes

- cinc-server-ng closes idle kept-alive connections after **2 minutes**. Keep
  the load balancer's idle timeout below that (the AWS ALB default of 60 s is
  fine). If it is longer, the server can close a connection just as the load
  balancer reuses it, which shows up as sporadic 502s.
- The server allows 10 s to receive request headers and sets no overall
  request timeout, so large cookbook transfers on slow links complete. Don't
  set a short overall timeout on the proxy either.
- Request bodies are capped at 1 GiB. Raise the proxy's limit to match what
  your largest cookbook file needs. nginx defaults to 1 MiB, which rejects
  ordinary cookbook uploads with `413`.

### nginx

```nginx
upstream cinc {
    server 127.0.0.1:8889;
    keepalive 32;
}

server {
    listen 443 ssl;
    http2 on;
    server_name chef.example.com;

    ssl_certificate     /etc/letsencrypt/live/chef.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chef.example.com/privkey.pem;

    client_max_body_size 1g;

    location / {
        proxy_pass http://cinc;            # no trailing slash: keep the path as signed
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
        proxy_request_buffering off;       # stream cookbook uploads
    }
}
```

Run cinc-server-ng with its default `--addr 127.0.0.1:8889`, so only the proxy
can reach it. A client that could connect to it directly would bypass the
proxy and could set `X-Forwarded-Proto` itself.

### Caddy

Caddy passes `Host` through and sets `X-Forwarded-Proto` by default, and
obtains and renews the certificate itself:

```caddy
chef.example.com {
    request_body {
        max_size 1GB
    }
    reverse_proxy 127.0.0.1:8889
}
```

### AWS

- **ALB** (TLS at the ALB): an HTTP target group on port 8889, health check
  path `/_status`, success code `200`. The ALB preserves `Host` and sets
  `X-Forwarded-Proto`, so no extra flags are needed. Set the target group's
  deregistration delay to at least `--shutdown-delay`.
- **NLB** with a TCP listener (TLS at cinc-server-ng): run with `--tls-cert`
  and `--tls-key`; health check over HTTPS to `/_status`. A TLS listener on the
  NLB terminates there instead, which behaves like the ALB case but without
  `X-Forwarded-Proto`, so set `--external-url`.

## Docker

```sh
docker run -p 443:8889 \
  -v /etc/cinc/tls:/tls:ro -v cinc-data:/data \
  -e CINC_SERVER_NG_TLS_CERT=/tls/server.crt \
  -e CINC_SERVER_NG_TLS_KEY=/tls/server.key \
  ghcr.io/cinc-project/cinc-server-ng:latest \
  --addr 0.0.0.0:8889 --storage sqlite --db /data/cinc.db --shutdown-delay 15s
```

The image's `HEALTHCHECK` (`cinc-server-ng healthcheck`) probes over TLS
whenever `CINC_SERVER_NG_TLS_CERT` is set, so configuring TLS through the
environment keeps the health check working. If you pass `--tls-cert` on the
command line instead, override the check with
`--health-cmd "/cinc-server-ng healthcheck --tls"`. The TLS probe does not
verify the certificate: it dials loopback, which the certificate does not name,
and it sends nothing and trusts nothing beyond the status code. Send `SIGHUP`
after renewing with `docker kill --signal HUP <container>`.

## What TLS costs

See [`benchmarks/v0.17.0-tls.md`](benchmarks/v0.17.0-tls.md). In short: on a
kept-alive connection, which is how chef-client and load balancers talk to the
server, the cost is small. A full handshake on every request is what's
expensive, so make sure clients and the load balancer reuse connections.
