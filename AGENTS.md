# AGENTS.md

## Project Overview

php-oauth1 is a small, dependency-light OAuth 1.0 (RFC 5849) signing and verification library for PHP 8.1+. It is a
companion to `php-oidc` (OAuth 2.0 / OpenID Connect) for the older one-legged OAuth 1.0 protocol that integrations
such as Basic LTI 1.0/1.1 still require: form-signed tool launches, currently. Solve the common case - signing and
verifying these one-legged, no-token requests - well, rather than chasing full three-legged OAuth 1.0 provider
coverage or LTI 1.1's Basic Outcomes Service (see Architecture for what that would add and why it is out of scope
today). This is library code consumed by other applications, not an application itself. A change here affects
every consumer, so keep the public API small, generic, and stable. Breaking changes are allowed but must be
deliberate and noted, never accidental.

Reference copies of the specs this library implements against live in `specs/`: RFC 5849 (OAuth 1.0 Protocol),
the Basic LTI v1.0 Implementation Guide, and the LTI v1.1 Implementation Guide (which added the Basic Outcomes
Service and `oauth_body_hash` signing). Consult them directly for signature base string construction, parameter
normalization, and percent-encoding rules rather than re-deriving them from memory.

## Commands

```sh
composer install                        # install dependencies
make phpunit                            # run the full test suite (vendor/bin/phpunit)
make phpstan                            # run static analysis (level 8, config in phpstan.neon)
make test                               # both of the above
vendor/bin/phpunit --filter TestClassName   # run one test class
composer update -W vendor/package       # update one dependency with its own dependents
php example/app.php                     # run the example application (see example/README.md)
```

CI (`.github/workflows/ci.yml`) runs `composer audit --locked`, `vendor/bin/phpunit`, and
`vendor/bin/phpstan analyse` against PHP 8.1 through 8.5. PHPStan is configured at level 8 over `src` only.
`test/` and `example/` are deliberately out of scope for now - add them back to `paths` in `phpstan.neon` when
they are ready. There is no configured code-style linter in this repository - do not assume `phpcs` exists.
`.editorconfig` covers whitespace only: PHP indents with tabs, everything else with spaces (2 for YAML and
Markdown, 4 otherwise).

- **Always scope dependency updates.** Use `composer update -W <vendor>/<package>` for a specific package plus its
  dependents. Never run an unbounded `composer update` - it can pull in breaking changes across the whole tree.
- **Dependency update policy.** Dependabot opens monthly update PRs for both Composer packages and GitHub Actions
  (`.github/dependabot.yml`) - review and merge those promptly rather than letting `composer.lock` drift.
  `composer audit --locked` runs in CI on every push and PR, so a runtime dependency with a known advisory fails
  the build instead of passing unnoticed; review the advisory and update the affected package (scoped, per the
  rule above) before merging past a failure there.

## Architecture

Two namespaces, `Oauth1\` and `BasicLti1\`, mirroring `src/Oauth1/` and `src/BasicLti1/` 1:1. `BasicLti1\` is a
thin layer on top of `Oauth1\` - every Basic LTI launch is just a signed, one-legged OAuth 1.0 request
underneath (no token, `oauth_callback` set to `about:blank`), plus a handful of mandatory launch parameters.

`Oauth1\` - RFC 5849 core:

- `Credentials` - the four values a request signs or verifies against (consumer key/secret, token/token secret).
- `SignatureMethod` - the three RFC 5849 §3.4 methods (HMAC-SHA1, RSA-SHA1, PLAINTEXT).
- `SignerInterface` / `VerifierInterface` - one pair per method. `HmacSha1Signer` and `PlaintextSigner` each
  implement both (a shared secret signs and verifies); `RsaSha1Signer`/`RsaSha1Verifier` are separate classes,
  since RFC 5849 only ever issues a client its own private key, never the public key that verifies against it.
- `SignatureBaseString` / `PercentEncoding` - the RFC 5849 §3.4.1/§3.6 base string and percent-encoding rules, as
  pure, unlogged computations shared by every signature method.
- `RequestSigner` / `RequestSignerFactory` - assembles the `oauth_*` parameters for one outgoing request and
  delegates the signature itself to the injected `SignerInterface`.
- `RequestVerifier` / `RequestVerifierFactory` - recomputes and checks an incoming request's signature, plus
  `oauth_version` and the consumer key, and - for HMAC-SHA1/RSA-SHA1 - a canonical, in-tolerance timestamp and
  nonce replay. The nonce is claimed only after the signature checks out, and its cache TTL spans the request's
  own timestamp window, not a flat tolerance from claim time - see the class's own docblock for why either
  ordering shortcut is a denial-of-service or replay vector, not just a tidiness concern.
- `NonceStore` - a thin PSR-16 cache wrapper `RequestVerifier` uses for replay detection. Internal collaborator,
  not part of the public surface (see Documentation).
- `NonceGeneratorInterface` / `RandomNonceGenerator`, `CurrentClock` - injectable nonce/time sources, so tests
  use fixed ones instead of real randomness/wall-clock time.
- `Truncate` / `PemPreview` - logging-safety helpers: capping an unbounded, not-yet-validated value before it
  reaches a log line, and describing an unreadable RSA key from its PEM boilerplate alone, never its bytes.
- `LogLevelFilterLogger` / `LogLevelFilterMode` - a generic PSR-3 decorator, ported from `php-oidc`, for routing
  only chosen log levels to a caller's own logger. Nothing about it is OAuth1-specific.
- `Exceptions\OAuth1Exception` (base), `SigningException` (a signer or verifier cannot even attempt one - a
  malformed URL, an unreadable RSA key, openssl rejecting the input, a nonce-cache write failure),
  `RequestVerificationException` (a signature was computed and checked, and failed - see
  `VerificationFailureReason` for every reason).

`BasicLti1\` - the launch layer:

- `Launch` - the fixed parameter names/values (`lti_message_type`, `lti_version`, `resource_link_id`) every
  Basic LTI launch requires.
- `LaunchRequest` - a signed launch's URL and parameters, data only - deliberately no markup; see its own
  docblock for why rendering it as an auto-submitting form is the consuming application's job, not this
  library's (`assets/auto-submit-form.php` is a copyable template for that job, not part of the library itself).
- `LaunchRequestBuilder` / `LaunchRequestBuilderFactory` - builds one launch: sets `lti_message_type`/
  `lti_version` regardless of what the caller supplied, requires `resource_link_id`, signs the whole parameter
  set via `Oauth1\RequestSigner` (the factory hard-wires HMAC-SHA1, the only method Basic LTI allows).
- `LaunchVerifier` / `LaunchVerifierFactory` - verifies an incoming launch: delegates OAuth 1.0 verification to
  `Oauth1\RequestVerifier` first and lets its exception propagate uncaught, then checks the Basic LTI-specific
  parameters only once the signature has already checked out.
- `Exceptions\BasicLti1Exception` (base), `InvalidLaunchException` (a Basic LTI parameter is missing or wrong,
  independent of whether the request was signed correctly).

Out of scope, deliberately: LTI 1.1's Basic Outcomes Service and the OAuth Body Hash extension
(`oauth_body_hash`, POX/XML requests with every OAuth parameter forced into the `Authorization` header). Stopped
short of it on purpose when this library was first built - revisit only as a deliberate, separate decision, not
an assumption baked into new work.

Follow `php-oidc`'s composition-over-inheritance convention here too: small collaborators wired together by a
factory, no `new` outside factories/tests, no capability grown as a private method on some larger class instead of
its own class.

## Code Style

- **Class design.** Small and single-purpose. Prefer composition over inheritance. Avoid traits, especially ones
  with state.
- **Mark classes `final` by default.** This repository's own convention differs from some sibling projects here:
  every class is `final` unless it is a deliberate extension point for a consuming application - the `Exceptions/`
  hierarchy (so callers can catch narrower or broader types) and any factory class wiring signers/verifiers together
  (wiring a consumer may want to override) are the expected carve-outs. Adding a new class that isn't one of those
  should be `final`.
- **Immutability.** Every value object here (expected: signed-request results, credentials, and any configuration
  object) is built from `readonly` properties. There are no mutable DTOs in this codebase - unlike some sibling
  projects, there is no carve-out for a "just a data bag" exception. A configuration-style object uses the cloning
  `with*()` pattern for every settable property - each constructor argument must have a matching `with<Property>()`
  method that returns a new instance. A property without one is a bug, not an oversight to leave for later.
- **Fail closed on anything security-relevant.** Signature mismatches, timestamp/nonce replay, and unknown
  consumer-key checks must throw a package exception when the expected value is missing, invalid, or ambiguous,
  never silently skip the check. A missing value because "it should always be there" is exactly the case that must
  still be verified.
- **Log levels.** Mirrors `php-oidc`'s own scheme exactly - see `docs/index.html`'s Logging section for the full
  level table, the curated `security_relevant: true` list, and the class-by-class table of what logs what. In
  short: `debug` traces the happy path, at every layer, on every successful `sign()`/`verify()`/`build()` call.
  `alert` is a configuration choice worth a developer's own review, logged on every use, not once - currently just
  PLAINTEXT signing/verifying, which "MUST only be used over TLS" and this library cannot enforce (see
  `PlaintextSigner`'s docblock). `error` is every failure, logged immediately before the exception it precedes is
  thrown - every throw site in `RequestSigner`, `RequestVerifier`, the two factories, `RsaSha1Signer`/
  `RsaSha1Verifier`, `LaunchRequestBuilder`, and `LaunchVerifier` has a paired `error()` call, no exceptions. Every
  `error()` call carries `security_relevant`, `true` only for `InvalidSignature`/`NonceReplayed` - the two outcomes
  unexplainable except as tampering or replay - `false` everywhere else, matching how `php-oidc`'s own curated list
  stays small (an expired token or audience mismatch is `false` there too). `warning` is deliberately unused: it
  marks a fail-open decision or a clean "nothing found" lookup in `php-oidc`, and this library has no fail-open
  path by design - every check either passes or throws. Revisit only if that changes.
  `SignatureBaseString`, `PercentEncoding`, and `NonceStore` log nothing themselves - pure computation or a thin
  cache wrapper with no independent failure surface; the layer that calls them is where the log line belongs.
  Revisit this note - and add a Logging section to `docs/index.html` - if that changes.
- **Typing.** Type every parameter and return, using native PHP types first and PHPDoc (`@param`, `@return`,
  array-shape syntax) only where types fall short or where an argument's shape needs documenting. Prefer `iterable`
  over `array` for arguments when either works.
- **Exceptions.**
  - Never throw a built-in PHP exception directly. Throw or extend an `Oauth1\Exceptions\*` type.
  - Every exception extends a single package base exception (itself a `\RuntimeException`), so all exceptions here
    are unchecked by convention - but still document `@throws` on any method that can throw one, so a caller can
    see the failure modes without reading the implementation.
  - Wrap exceptions from external calls (hashing/crypto failures, malformed input) into a package exception; do not
    let a raw runtime exception escape a public method.
  - Exception messages: no trailing punctuation, and never assume they are safe to show an end user as-is.
- **Docblocks explain why, not what.** Every file in `src/` opens with a docblock giving the rationale for the
  class existing and the design tradeoff it makes (following `php-oidc`'s pattern of naming the specific tradeoff,
  not just restating the class name). A docblock that only restates the class name in sentence form is not useful -
  delete it or replace it with the actual reasoning.
- **Writing style.** Terse, Hemingway-style. Short sentences. No contractions, no jargon. Spell out an acronym on
  first use.

## Testing

- One test file per class, named `<ClassName>Test.php`, mirroring the `src/` structure 1:1. When a class gains a
  new public method or constructor parameter, its own test file gets new test methods - do not rely on an
  end-to-end test elsewhere to stand in for unit coverage of the class actually changed.
- This repository does not use PHPUnit data providers; each behavior gets its own `test<Description>(): void`
  method, matching every existing test file. Do not introduce a data-provider-driven test here just because it is
  a common pattern elsewhere - match what is already in `test/`.
- Aim for full coverage of every branch a change introduces, including enum/mode decision matrices (e.g. every
  signature-method case) and every `with*()` wither, not just the happy path. An exemption is reasonable only for
  a branch that is truly unreachable or purely defensive.
- Prefer real objects over mocks. There is no `test/Fakes/` yet - when one is needed (a `FixedClock` for
  timestamp/nonce checks and an `RsaKeyFixture` for `RSA-SHA1` are the likely first ones, following `php-oidc`'s
  pattern), add it there rather than reaching for mocking infrastructure.
- When a value is defined by a spec (a signature base string, an `oauth_body_hash`), assert against a known test
  vector from `specs/` where one exists, not only against the library's own encoding of the same input.

## Documentation

- `docs/index.html` is the rendered public API reference (served via GitHub Pages from `dev`), styled and structured
  after `php-oidc`'s own copy (same CSS, same `type-section`/`method-sig`/index/footer conventions).
- **Every commit that touches `src/` must leave `docs/index.html` in sync in that same commit, never a follow-up.**
  This is not limited to "public API changes" as a judgment call - treat it as unconditional: a new class,
  interface, method, constructor parameter, `with*()` wither, enum case, exception type, or a changed docblock
  rationale worth surfacing all need a matching update there before the commit is done. A commit that changes
  `src/` and does not touch `docs/index.html` should be treated as incomplete unless the change is purely internal
  (see the exclusion list below) - and even then, double-check rather than assume.
- It documents the public surface only. Internal collaborators - the signature base string builder
  (`SignatureBaseString`), the percent-encoding helper (`PercentEncoding`), and `NonceStore` (which wraps a PSR-16
  cache the same way `php-oidc`'s `AuthorizationStateStore` does) - are deliberately excluded. Everything else
  under `Oauth1\`, `Oauth1\Exceptions\`, `BasicLti1\`, and `BasicLti1\Exceptions\` is documented, including the
  factories, both signer/verifier interfaces and their concrete implementations, and every value object and enum.

## Git

- Default branch is `dev`. Treat it as the merge target for pull requests, not a branch to commit to directly.
- Every branch is cut from `dev`, and every PR targets `dev` - never another feature branch, matching `php-oidc`'s
  own convention. This holds even when new work genuinely depends on something only a not-yet-merged branch has
  (a test fake, a helper class): branch from `dev` anyway and duplicate the small dependency if needed, or wait
  for the dependency to land in `dev` first, rather than stacking. A branch merged into another branch instead of
  `dev` is invisible to `dev` unless that branch is later re-merged too - exactly the bug a stacked branch caused
  once already (PR #11 targeted `feature/logging` instead of `dev`, merged into it after `feature/logging` had
  already been merged into `dev`, and was stranded until a follow-up PR re-merged it).
- Keep commits focused. A commit that adds a feature and a commit that hardens/tests it are both fine as separate
  commits; do not squash a branch down to one commit by default.
