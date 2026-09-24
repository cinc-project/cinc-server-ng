# Generates golden authentication vectors using the real Chef
# mixlib-authentication gem. Run: ruby gen_vectors.rb > vectors.json
#
# The Go verifier tests consume vectors.json to prove byte-for-byte
# compatibility with real chef-client / knife / cinc request signing.
require "openssl"
require "digest"
require "json"
require "uri"
require "mixlib/authentication/signedheaderauth"

# Fixed key generated once and embedded in the output so vectors are stable.
# Regenerating reuses the key already in vectors.json (RSASSA-PKCS1-v1_5 is
# deterministic, so the existing vectors come out byte-identical).
existing = File.join(__dir__, "vectors.json")
key = if File.exist?(existing)
        OpenSSL::PKey::RSA.new(JSON.parse(File.read(existing))["private_key"])
      else
        OpenSSL::PKey::RSA.new(2048)
      end

REQUESTS = [
  { http_method: :get,    path: "/organizations/acme/nodes",          body: "",                       user_id: "test-client" },
  { http_method: :post,   path: "/organizations/acme/nodes",          body: '{"name":"web01"}',         user_id: "test-client" },
  { http_method: :put,    path: "/organizations/acme/nodes/web01",    body: '{"name":"web01","run":1}',  user_id: "test-client" },
  { http_method: :delete, path: "/organizations/acme/data/secrets",   body: "",                       user_id: "user@example.com" },
  # path canonicalization edge cases
  { http_method: :get,    path: "/organizations/acme//nodes/",        body: "",                       user_id: "test-client" },
  # Percent-escaped paths. Chef::HTTP::Authenticator signs `url.path`, the
  # escaped path as it goes on the wire, so these paths come from a parsed
  # URI the same way.
  { http_method: :delete, path: URI("https://chef.example/organizations/acme/data/t%20bad%2095bd2c97").path, body: "", user_id: "test-client" },
  { http_method: :get,    path: URI("https://chef.example/organizations/acme/data/bag/bad%20id").path,       body: "", user_id: "test-client" },
].freeze

cases = []
%w[1.0 1.1 1.3].each do |ver|
  REQUESTS.each do |req|
    ts = "2024-01-02T03:04:05Z"
    sav = "1"
    # server_api_version is read from the request headers (see mixlib
    # SigningObject#server_api_version), so we pass it the way a real client
    # would and record it in the emitted headers below.
    signer = Mixlib::Authentication::SignedHeaderAuth.signing_object(
      http_method: req[:http_method],
      path: req[:path],
      body: req[:body],
      timestamp: ts,
      user_id: req[:user_id],
      proto_version: ver,
      headers: { "X-Ops-Server-API-Version" => sav },
    )
    headers = signer.sign(key)
    headers["X-Ops-Server-API-Version"] = sav
    cases << {
      proto_version: ver,
      http_method: req[:http_method].to_s.upcase,
      path: req[:path],
      body: req[:body],
      timestamp: ts,
      user_id: req[:user_id],
      server_api_version: "1",
      headers: headers.transform_keys(&:to_s),
    }
  end
end

puts JSON.pretty_generate(
  "public_key" => key.public_key.to_pem,
  "private_key" => key.to_pem,
  "cases" => cases,
)
