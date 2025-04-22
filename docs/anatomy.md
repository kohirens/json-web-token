
**JWTs** - represent a set of claims as a `JSON object` that is encoded in a
JWS and/or JWE structure. Is represented as a sequence of URL-safe parts
separated by period ('.') characters; each part is base64url-encoded.

The number of parts depends on if it represents JWS Compact Serialization or
JWE Compact Serialization.

Parts may consist of zero or more name/value pairs (or members).

**name/value pairs** - Names are (strings) within the JWT Claims Set are
referred to as Claim Names. Values are (arbitrary JSON values) referred to as
Claim Values.

**JOSE Header** contents describe the cryptographic operations applied to the
JWT Claims Set.

If for a JWS, then the JWT Claims Set is the JWS Payload and are digitally
signed or MACed with the algorithm specified.

If for a JWE, then the claims are encrypted; with the JWT Claims Set being the
plaintext encrypted by the JWE.

For example a JOSE Header can declare the encoded object is
a JWT, and the JWT is a JWS that is MACed using the HMAC SHA-256
algorithm:
```JSON
{"typ":"JWT",
 "alg":"HS256"}
```
