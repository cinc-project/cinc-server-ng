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
  `{"status":"pong",...}` when serving, `500` with `{"status":"fail",...}` when
  the store does not answer a ping within 400 ms (for example a closed or
  unreadable SQLite database), and `503` with `{"status":"draining"}` while
  shutting down. The body has Chef Infra Server's shape: `upstreams` reports
  `chef_sql` (the store backend), `chef_solr` (the in-process search index) and
  `oc_chef_authz` (in-process authorization) as `pong` or `fail`; `keygen` is
  all zeros, since keys are generated per request rather than from a
  pre-generated pool; `indexing.mode` is `inline`, since writes update the
  search index before the request returns.
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
- Request bodies are on a clock, `--body-timeout` (default `2m`). An API body
  is read before its signature is checked, so it must arrive whole within that
  time, or the connection is closed; a full 2,000,000-byte body needs about
  130 kbit/s. A cookbook file upload has no overall limit and is closed only
  after it sends nothing for that long, like nginx's `client_body_timeout`.
  A negative value turns this off.
- `--max-connections` (default `0`, no limit) caps the client connections held
  open at once; more wait in the listen backlog until one closes. If you set
  it, leave room for your fleet's concurrent chef-client runs plus the load
  balancer's kept-alive connections, and keep it below the process's open file
  limit.
- API request bodies are capped at 2,000,000 bytes (`--max-request-size`) and
  cookbook files at 250 MiB (`--max-file-size`), Chef Infra Server's defaults;
  larger ones get `413`. Set the proxy's limit to at least the file cap. nginx
  defaults to 1 MiB, which rejects ordinary cookbook uploads with `413`.

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

    client_max_body_size 250m;

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
        max_size 250MiB
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

## Running cinc-console against it

[cinc-console](https://github.com/cinc-project/cinc-console) signs every
request with a **webui key** and names the logged-in user
(`X-Ops-Request-Source: web`). The server checks the signature against its
webui public key, then applies that user's ACLs. Whoever holds the webui
private key can act as any user, the superuser included.

### Give the console its own key

By default the webui key **is** the bootstrap admin key. That's convenient in
development ([DEVELOPMENT.md](DEVELOPMENT.md#connecting-cinc-console)), but it
hands `pivotal`'s private key to the console. In production, generate a
dedicated pair and give the server only the public half:

```sh
openssl genrsa -traditional -out webui_priv.pem 2048
openssl rsa -in webui_priv.pem -pubout -out webui_pub.pem

cinc-server-ng --storage sqlite --db /data/cinc.db \
  --webui-key /data/webui_pub.pem
```

- `--webui-key` accepts a public key (`PUBLIC KEY` or `RSA PUBLIC KEY`) as
  well as a private key, so `webui_priv.pem` never has to be on the server.
  The startup banner names the key in use
  (`webui impersonation: enabled (key: ...)`).
- Give `webui_priv.pem` to the console (`CINC_WEBUI_KEY_FILE`) and to nothing
  else.
- The admin key and the webui key rotate independently. To rotate the webui
  key, generate a new pair, replace both files, and restart both processes.

Without `--webui-key`, the webui key is whichever keys `pivotal` can sign
with at the moment of each request: its unexpired keys, as
`GET /users/pivotal/keys` lists them, and only while `pivotal` is the
superuser. Rotating `pivotal`'s key through the keys API therefore rotates
the webui key too: the old key stops working for the console at once, and
the console must be given the new private key.

`--key-out` writes the private key the server bootstrapped `pivotal` with,
the only one it holds. Once `pivotal` has replaced, deleted or let that key
expire, `--key-out` leaves the file as it is and prints a warning rather
than write a key that no longer authenticates; keep the new key yourself.

### Create a user to log in as

The console logs users in with a password, which it checks with
`POST /authenticate_user`. A fresh server has only `pivotal`, which has a key
but no password. The simplest fix is to have the server create the first
admin at startup:

```sh
cinc-server-ng --storage sqlite --db /data/cinc.db --orgs myorg \
  --webui-key /data/webui_pub.pem --key-out /data/pivotal.pem \
  --bootstrap-user alice --bootstrap-password-file /run/secrets/alice
```

`alice` is created with that password, joins the global `server-admins` group
(so she can create users and organizations) and becomes a member and admin of
every `--orgs` org. The password comes from the file (one trailing newline is
dropped) or from `CINC_SERVER_NG_BOOTSTRAP_PASSWORD`; there is no password
flag. Set `--bootstrap-email` for a real address (the default is
`alice@localhost.localdomain`). On every later start the user is left as it is,
so a password changed through the console or `cinc user password` survives a
restart; only the memberships are re-applied. `--key-out` is still how you get
`pivotal`'s key.

Or create users by hand, as `pivotal`, with
[cinc-cli](https://github.com/cinc-project/cinc-cli) (or the equivalent `knife`
commands):

```sh
cinc user create alice --email alice@example.com \
  --first-name Alice --last-name Smith --password '...' --key-file alice.pem
cinc org member add alice            # joins the org's "users" group: read access
cinc group member add admins alice   # optional: full control of the org
```

`--key-file` saves the user's own API key, so the same account also works from
the command line. Users change their password with `cinc user password <name>`.

Point the console at the server root, without `/organizations/<org>`
(`CINC_SERVER_URL=https://chef.example.com`). If the console goes through the
same proxy as other clients, the notes above about `Host` and
`X-Forwarded-Proto` apply unchanged.

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

### Docker Compose, hardened

The binary writes only to the SQLite database (and `--key-out`, if set), so
the container runs with a read-only root filesystem, no capabilities and no
privilege escalation. The volume is its only writable path.

```yaml
services:
  cinc-server-ng:
    # Pin a release, ideally by digest: ghcr.io/cinc-project/cinc-server-ng:<version>@sha256:<digest>
    image: ghcr.io/cinc-project/cinc-server-ng:<version>
    restart: unless-stopped
    user: "65532:65532"        # the image's nonroot user, set explicitly
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    command:
      - --addr=0.0.0.0:8889
      - --storage=sqlite
      - --db=/data/cinc.db
      - --orgs=acme
      - --key-out=/data/pivotal.pem
      - --shutdown-delay=5s
    environment:
      # Set in .env next to this file (or your secret store), not inline.
      CINC_SERVER_NG_STATS_PASSWORD: ${CINC_STATS_PASSWORD:?set CINC_STATS_PASSWORD}
    ports:
      - "127.0.0.1:8889:8889"  # loopback: a TLS proxy on the host fronts it
    volumes:
      - cinc-data:/data

volumes:
  cinc-data:
```

- **The volume must be writable by UID 65532.** A new named volume takes its
  ownership from the image's `/data`, so it works as is. For a bind mount,
  create the directory first and `chown 65532:65532` it; mode `0700` keeps
  other host users out of the database and keys.
- **Bind to loopback, or to an internal network,** when a proxy terminates TLS
  in front of the server, for the reasons given under "Behind a reverse proxy
  or load balancer". To serve TLS from the container itself, add the
  `CINC_SERVER_NG_TLS_*` settings shown above and publish the port on the
  public interface instead.
- **One replica.** Don't scale this service (see "Run one active instance").
- The image's `HEALTHCHECK` applies unchanged, and `docker compose ps` shows
  `healthy` once `/_status` answers.

## What TLS costs

See [`benchmarks/v0.17.0-tls.md`](benchmarks/v0.17.0-tls.md). In short: on a
kept-alive connection, which is how chef-client and load balancers talk to the
server, the cost is small. A full handshake on every request is what's
expensive, so make sure clients and the load balancer reuse connections.
