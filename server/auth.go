package server

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/api"
	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// authMiddleware verifies the Mixlib signed-header authentication on every
// request (except unauthenticated system paths) before delegating to next.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// System paths (e.g. /_status) are unauthenticated.
		if api.SystemPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// /_stats takes HTTP Basic credentials instead of a signature, as
		// Chef Infra Server's nginx demands (see stats_auth.go).
		if r.URL.Path == statsPath {
			if !s.statsAuthorized(r) {
				statsUnauthorized(w)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// The cookbook file store is exempt from Mixlib signing: in real Chef
		// the sandbox hands back pre-signed bookshelf URLs that
		// knife/chef-client/cinc-client PUT/GET without signing them. cinc-server-ng
		// reproduces that shape, so authorization rides on the URL — the grant
		// the server issued, scoped to this org, checksum, and operation.
		if org, checksum, ok := fileStoreRequest(r); ok {
			if err := auth.VerifyFileStore(s.fileStoreKey, org, checksum,
				fileStoreOp(r.Method), r.URL.Query(), s.opts.Now()); err != nil {
				unauthorized(w, err.Error())
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Everything that can be judged from the headers is judged before the
		// body is read, as erchef's malformed_request does: the signing
		// headers, the clock, and the declared size. A request refused here
		// costs no body read at all.
		parsed, err := auth.Parse(r.Header)
		if err != nil {
			unauthorized(w, err.Error())
			return
		}
		if err := s.checkSkew(parsed.Timestamp); err != nil {
			unauthorized(w, err.Error())
			return
		}
		limit := s.bodyLimit(r)
		if limit > 0 && r.ContentLength > limit {
			api.WriteTooLarge(w, "JSON", limit)
			return
		}

		// Management-console impersonation: when a request is sourced from the
		// web UI, its signature is made with the webui key (not the actor's own
		// key) and X-Ops-Userid names the user being acted for. Verify against
		// the webui key and run as that user. This mirrors Chef Infra Server's
		// webui-key mechanism, which a console uses to honor each user's ACLs.
		if strings.EqualFold(r.Header.Get("X-Ops-Request-Source"), "web") {
			// The actor is resolved before the body is read: a name that runs
			// as no one is refused unread. (The signed path below reads the
			// body for an unknown name too; see authFailed.)
			candidates, err := s.resolveAuth(r.URL.EscapedPath(), parsed.UserID)
			if err != nil {
				serverError(w, err)
				return
			}
			// erchef's select_user_or_webui_key: web requests are user based,
			// so of a same-named user and client the user is the actor
			// (resolveAuth lists it first). erchef takes whichever requestor
			// comes first, so a name only a client can sign with (no user, or
			// a user with no unexpired key, which erchef's keys_by_name leaves
			// out too) would run as the client. A user can rename itself onto
			// a client's name and drop its keys, so that is refused here, with
			// erchef's answer for a requestor it cannot find.
			if len(candidates) == 0 || candidates[0].actor.IsClient {
				s.authFailed(w, r, parsed.UserID, "web UI request names no user that can sign")
				return
			}
			body, ok := readSignedBody(w, r)
			if !ok {
				return
			}
			webuiPubs, err := s.webuiKeys(candidates[0])
			if err != nil {
				serverError(w, err)
				return
			}
			prepared, err := auth.Prepare(r.Method, wirePath(r.URL), body, parsed, r.Header.Get("X-Ops-Server-API-Version"))
			if err != nil || !prepared.VerifyAny(webuiPubs) {
				s.authFailed(w, r, parsed.UserID, "web UI signature did not verify against the webui key")
				return
			}
			actor := candidates[0].actor
			actor.ViaWebUI = true
			r = r.WithContext(api.WithActor(r.Context(), actor))
			next.ServeHTTP(w, r)
			return
		}

		// Every actor answering to the name, with every key it may sign with
		// (its unexpired keys, as the keys API lists them). The actor is the
		// one whose key verifies the signature, as in erchef's
		// verify_request_signature: a user and a client may share a name, and
		// the key, not the name, says which of them signed.
		candidates, err := s.resolveAuth(r.URL.EscapedPath(), parsed.UserID)
		if err != nil {
			serverError(w, err)
			return
		}
		// The body is read, and a signature checked, whether or not anyone
		// answers to the name: see authFailed for why.
		body, ok := readSignedBody(w, r)
		if !ok {
			return
		}
		// The signing string, body hash included, is built once for the
		// request: an actor may hold any number of keys, and trying another
		// costs only its RSA step, never another pass over the body.
		prepared, err := auth.Prepare(r.Method, wirePath(r.URL), body, parsed, r.Header.Get("X-Ops-Server-API-Version"))
		if err != nil {
			unauthorized(w, err.Error())
			return
		}
		if len(candidates) == 0 {
			// A stand-in verification, so that an unknown name costs about
			// what a known one with a bad signature does. Its result is
			// ignored: nobody answers to the name, whatever key signed.
			prepared.VerifyAny([]*rsa.PublicKey{s.standInKey()})
			s.authFailed(w, r, parsed.UserID, "no such actor, or it has no unexpired key")
			return
		}
		var actor api.Actor
		verified := false
		for _, c := range candidates {
			// Chef Infra Server tries each of the requestor's unexpired keys
			// in turn; VerifyAny tries each distinct one.
			if prepared.VerifyAny(c.pubs) {
				actor, verified = c.actor, true
				break
			}
		}
		if !verified {
			s.authFailed(w, r, parsed.UserID, "signature did not verify against any of the actor's keys")
			return
		}

		// Carry the verified actor for the authorization layer (a no-op unless
		// EnforceACL is set).
		r = r.WithContext(api.WithActor(r.Context(), actor))
		next.ServeHTTP(w, r)
	})
}

// wirePath returns the request path exactly as the client sent it, percent
// escapes included, which is what a Mixlib client signs and what erchef
// verifies. url.URL keeps the received path verbatim in RawPath whenever it
// differs from the default encoding of Path; when RawPath is empty, that
// default encoding is exactly what was received. The decoded u.Path must
// never be verified: many encodings share one decoded path, and the client
// signed only the one it sent.
func wirePath(u *url.URL) string {
	if u.RawPath != "" {
		return u.RawPath
	}
	return u.EscapedPath()
}

// authCandidate is an actor a request may be signed by, with its keys.
type authCandidate struct {
	pubs  []*rsa.PublicKey
	actor api.Actor
}

// resolveAuth returns every actor answering to name on this path, each with
// the keys it may sign with: the global user, then (when the request targets
// an org) the org's client of that name. That is erchef's order
// (chef_sql:fetch_actors_by_name sorts users before clients), and it matters
// when one key verifies for both: a client registered with a user's public
// key, which anyone may read, must not capture that user's requests. The actor
// records whether it is an org client and whether a global user is an admin
// (Chef's pivotal superuser, which bypasses ACLs).
//
// A client is looked up first so that the common case, a node signing as its
// client with no user of its name, reads one record as it always has: the
// user is skipped only when s.users says no user has the name.
func (s *Server) resolveAuth(path, name string) ([]authCandidate, error) {
	var client *authCandidate
	if org := orgFromPath(path); org != "" {
		o, found, err := s.store.Org(org)
		if err != nil {
			return nil, err
		}
		if found {
			pubs, _, ok, err := s.parseActorRecord(o, "clients", name)
			if err != nil {
				return nil, err
			}
			if ok {
				client = &authCandidate{pubs, api.Actor{Name: name, IsClient: true}}
			}
		}
	}
	var out []authCandidate
	if client == nil || s.users.has(name) {
		pubs, admin, ok, err := s.parseActorRecord(s.store.Global(), "users", name)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, authCandidate{pubs, api.Actor{Name: name, IsGlobalAdmin: admin}})
		}
	}
	if client != nil {
		out = append(out, *client)
	}
	return out, nil
}

// webuiKeys returns the keys a web-UI request (X-Ops-Request-Source: web) may
// be signed with. A configured WebUIKey is the only one. Without it, the webui
// key is the bootstrap admin's: every key the admin user may sign with now
// (its unexpired keys, as resolveAuth reads them), and none once the user no
// longer carries the superuser flag. Reading them per request, rather than
// fixing the bootstrap key at startup, is what makes a key the admin rotates
// away, deletes or lets expire stop impersonating users, and lets a console
// moved to the admin's new key keep working. A request made as the admin
// itself reuses the keys already read for it.
func (s *Server) webuiKeys(actor authCandidate) ([]*rsa.PublicKey, error) {
	if s.webuiPub != nil {
		return []*rsa.PublicKey{s.webuiPub}, nil
	}
	if !actor.actor.IsClient && actor.actor.Name == s.opts.AdminName {
		if !actor.actor.IsGlobalAdmin {
			return nil, nil
		}
		return actor.pubs, nil
	}
	pubs, admin, ok, err := s.parseActorRecord(s.store.Global(), "users", s.opts.AdminName)
	if err != nil || !ok || !admin {
		return nil, err
	}
	return pubs, nil
}

// standInKey is the key an unknown actor's signature is checked against, for
// timing only (see authFailed): the configured webui key, else the admin's
// bootstrap key.
func (s *Server) standInKey() *rsa.PublicKey {
	if s.webuiPub != nil {
		return s.webuiPub
	}
	return s.adminPub
}

// parseWebUIKey accepts a PEM-encoded RSA public or private key and returns the
// public key used to verify web-sourced (management-console) requests.
func parseWebUIKey(pemBytes []byte) (*rsa.PublicKey, error) {
	if pub, err := auth.ParsePublicKey(pemBytes); err == nil {
		return pub, nil
	}
	priv, err := auth.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	return &priv.PublicKey, nil
}

// parseActorRecord reads an actor record from a store collection and returns
// the RSA public keys it may currently sign with (api.SigningKeys: its
// unexpired keys, parsed through the server's key cache to avoid re-parsing
// PEM/x509 on every request) and its admin flag. ok is false when the actor
// does not exist or has no usable key. The record is read copy-free since it
// is only unmarshalled here.
func (s *Server) parseActorRecord(org *store.Org, collection, name string) (pubs []*rsa.PublicKey, admin, ok bool, err error) {
	raw, found, err := org.View(collection, name)
	if err != nil {
		return nil, false, false, err
	}
	if !found {
		return nil, false, false, nil
	}
	// Read each member by its exact name, never by struct-tag decoding:
	// encoding/json matches names case-insensitively, so a record holding
	// "Admin" or "PUBLIC_KEY" (ordinary profile data an actor may write into
	// its own record) would otherwise be read as the superuser flag or a key.
	rec, err := chefjson.DecodeObject(raw)
	if err != nil {
		return nil, false, false, nil
	}
	publicKey, _ := rec["public_key"].(string)
	admin = rec["admin"] == true
	pems, err := api.SigningKeys(org, collection, name, publicKey, s.opts.Now())
	if err != nil {
		return nil, false, false, err
	}
	for _, pem := range pems {
		if key, err := s.keyCache.Parse(pem); err == nil {
			pubs = append(pubs, key)
		}
	}
	if len(pubs) == 0 {
		return nil, false, false, nil
	}
	return pubs, admin, true, nil
}

// checkSkew rejects timestamps outside the allowed clock-skew window.
func (s *Server) checkSkew(timestamp string) error {
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return skewError{"invalid X-Ops-Timestamp"}
	}
	delta := math.Abs(s.opts.Now().Sub(ts).Seconds())
	if delta > float64(s.opts.SkewSeconds) {
		return skewError{"Original request time stamp too far in the future or past."}
	}
	return nil
}

type skewError struct{ msg string }

func (e skewError) Error() string { return e.msg }

// authFailed refuses a request whose signature could not be tied to an actor.
//
// Every such failure answers with one message, erchef's for a requestor it
// cannot find, whether the name is unknown, names an actor whose keys have all
// expired, names a client on a web-UI request, or names a real actor whose key
// did not verify. erchef says "Invalid signature for user or client" in the
// last case, which tells anyone who can reach the server, without any
// credential, which user and client names exist. cinc-server-ng deliberately
// differs from erchef here (differential/known.go). The message echoes only
// the name the caller sent; the specific reason goes to the server's log.
//
// Timing: an unknown name still has its body read and one signature checked
// (against the webui key, standing in), so it does about the work of a known
// name with one key. What remains is small: the store reads differ, and a
// known actor with several keys has each of them tried.
func (s *Server) authFailed(w http.ResponseWriter, r *http.Request, name, reason string) {
	s.opts.Logger.Info("authentication failed",
		"actor", name, "method", r.Method, "path", r.URL.Path, "reason", reason)
	unauthorized(w, "Failed to authenticate as '"+name+"'. Ensure that your node_name and client key are correct.")
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": []string{msg}})
}

// serverError reports a backend failure (e.g. a store read error during auth
// resolution) as a JSON 500, so a storage fault is never silently treated as an
// authentication failure.
func serverError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": []string{err.Error()}})
}

// readSignedBody reads a signed request's body, which the outer limitBody
// caps, and hands it on buffered. A body that runs past the cap (one sent
// chunked, or longer than it declared) is refused as erchef refuses it.
func readSignedBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := api.ReadBody(r.Body, r.ContentLength)
	if err != nil {
		if tooBig, ok := errors.AsType[*http.MaxBytesError](err); ok {
			api.WriteTooLarge(w, "JSON", tooBig.Limit)
			return nil, false
		}
		unauthorized(w, "could not read request body")
		return nil, false
	}
	r.Body = api.BufferBody(body)
	return body, true
}

// bodyLimit is the most of r's body the server reads: the cookbook file
// store's cap for a file upload, the API cap for everything else. Zero or less
// means no cap. Whether r is a file upload is fileStoreRequest's answer, the
// same one that exempts it from signing, so a request held to the file
// store's cap is always one that must carry a file-store grant.
func (s *Server) bodyLimit(r *http.Request) int64 {
	if _, _, ok := fileStoreRequest(r); ok {
		return s.opts.MaxFileStoreBytes
	}
	return s.opts.MaxBodyBytes
}

// limitBody caps every request body, on every path, at bodyLimit, so that no
// layer (auth, or a handler on an auth-exempt path) can read more than that
// into memory. Reading past the cap fails with *http.MaxBytesError. It also
// puts the body on Options.BodyTimeout's clock, ahead of authentication: an
// API body must arrive whole within it, a file-store upload must not stall
// for longer than it.
func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, fileStore := fileStoreRequest(r)
		withBodyDeadline(w, r, s.opts.BodyTimeout, fileStore)
		if limit := s.bodyLimit(r); limit > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// enforceBodySize refuses, with erchef's 413, a body that authMiddleware has
// not already read: every body when authentication is off, and file-store
// uploads, which carry a pre-signed URL instead of a signature. A body
// declared over the cap is refused unread; any other API body is read here,
// under the cap, so that one running past it is a 413 rather than whatever
// its handler makes of a failed read. A file-store body is left to stream to
// its handler, which reports an overrun itself. The system endpoints and
// /_stats take no body, so one sent to them is never read.
func (s *Server) enforceBodySize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := s.bodyLimit(r)
		if limit <= 0 || r.Body == nil || r.Body == http.NoBody || api.IsBuffered(r.Body) ||
			api.SystemPaths[r.URL.Path] || r.URL.Path == statsPath {
			next.ServeHTTP(w, r)
			return
		}
		_, _, fileStore := fileStoreRequest(r)
		if r.ContentLength > limit {
			what := "JSON"
			if fileStore {
				what = "File"
			}
			api.WriteTooLarge(w, what, limit)
			return
		}
		if fileStore {
			next.ServeHTTP(w, r)
			return
		}
		body, err := api.ReadBody(r.Body, r.ContentLength)
		if err != nil {
			if tooBig, ok := errors.AsType[*http.MaxBytesError](err); ok {
				api.WriteTooLarge(w, "JSON", tooBig.Limit)
				return
			}
			writeBadRequest(w, "could not read request body")
			return
		}
		r.Body = api.BufferBody(body)
		next.ServeHTTP(w, r)
	})
}

// writeBadRequest reports a request the server could not take in as a JSON 400.
func writeBadRequest(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": []string{msg}})
}

// fileStoreRequest reports whether r is a cookbook file-store transfer, judged
// from its escaped path as the router routes it. It is the one decision behind
// both the exemption from signing and the body cap: a path that only decodes
// to the file store's shape (file_store%2Fx) is neither exempt nor given the
// file store's cap.
func fileStoreRequest(r *http.Request) (org, checksum string, ok bool) {
	return fileStorePath(r.URL.EscapedPath())
}

// fileStorePath reports whether path addresses the cookbook file store
// (/organizations/{org}/file_store/{checksum}, escaped and split as the router
// splits it), returning the org and checksum a pre-signed grant must cover.
func fileStorePath(path string) (org, checksum string, ok bool) {
	parts := api.PathSegments(path)
	if len(parts) != 4 || parts[0] != "organizations" || parts[2] != "file_store" {
		return "", "", false
	}
	return parts[1], parts[3], true
}

// fileStoreOp names the grant a request needs: an upload grant must not be
// replayable as a download, or the reverse.
func fileStoreOp(method string) string {
	if method == http.MethodPut || method == http.MethodPost {
		return auth.FileStorePut
	}
	return auth.FileStoreGet
}

// orgFromPath extracts the organization name from an escaped
// "/organizations/{org}/..." request path, split as the router splits it, or
// "" if the path is not org-scoped.
func orgFromPath(path string) string {
	parts := api.PathSegments(path)
	if len(parts) < 2 || parts[0] != "organizations" {
		return ""
	}
	return parts[1]
}
