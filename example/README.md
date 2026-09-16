# Example harness

Two small, real web apps - a simulated Tool Consumer (an LMS) and a simulated Tool Provider (a
tool) - that exercise a full Basic LTI 1.0 launch over real HTTP, using this library on both
sides. Unlike a typical "example" of mocked one-shot scripts, this is closer in spirit to
`php-oidc`'s `compliance/` harness: something you actually run and click through in a browser,
because a signed request round-tripping through two real HTTP servers is a meaningfully
different (and more convincing) test than two objects talking to each other in the same PHP
process.

## Running it

From the repository root:

```sh
composer install
./example/run.sh
```

This starts both apps with PHP's built-in dev server: the Tool Consumer on
<http://127.0.0.1:8091/>, the Tool Provider on <http://127.0.0.1:8092/>. Ctrl+C stops both.

To run them by hand instead, in two terminals from `example/`:

```sh
php -S 127.0.0.1:8091 -t tool-consumer
php -S 127.0.0.1:8092 -t tool-provider
```

Open <http://127.0.0.1:8091/> and:

- **Launch** builds a fresh, correctly signed launch and shows the form that carries it (view
  source to see every hidden field, including the `oauth_*` ones `LaunchRequestBuilder`
  produced) - submitting it should show **ACCEPTED** on the Tool Provider.
- **Replay last launch** resends the exact same signed request, unchanged - the Tool Provider's
  nonce store should reject it as already used.
- **Tamper with last launch** resends it with `roles` changed after signing, without re-signing -
  the Tool Provider should reject it as an invalid signature.

## No Caddy here

`php-oidc`'s `compliance/` harness needs Caddy because the OpenID Foundation conformance suite's
own redirect_uri validation requires `https` for anything other than the plain authorization
code flow. Nothing about Basic LTI has an equivalent requirement - HMAC-SHA1 signature
verification does not care what transport carried the bytes - so plain `http` via `php -S` is
enough to demonstrate every check this harness exercises. A real deployment should still use
`https`, but that is a deployment concern, not something this local demo needs to model.

## How it is built

- `harness/Config.php` - the shared consumer key/secret and both apps' URLs, exactly what a real
  Tool Consumer and Tool Provider would agree on out of band before any launch happens.
  Hardcoded, since this is a local demo, not a real integration.
- `harness/FileCache.php` - a PSR-16 cache backed by a JSON file on disk. `NonceStore` needs
  somewhere durable to record a nonce as used; php's built-in dev server starts a fresh process
  per request, so an in-memory cache would forget every nonce the instant the request that
  recorded it ended. This stands in for whatever real cache (Redis, Memcached, a database table)
  a production Tool Provider would use instead.
- `tool-consumer/index.php` / `tool-provider/index.php` - each a single front controller, plain
  procedural code (no framework), since the point here is to show the library's own public API
  doing the work, not this harness's own architecture.

Neither app renders anything beyond hidden `<input>` fields and a plain HTML form - no
`<script>` tag, no auto-submit. A generic library cannot know a consuming application's
Content-Security-Policy (myON's, for instance, requires a `nonce` on every script tag), so
`BasicLti1\LaunchRequest` only ever hands back data, and turning it into markup - auto-submitting
or not - is left to whoever is actually deploying it. This harness's own submit button follows
that same boundary on purpose, rather than special-casing itself.
