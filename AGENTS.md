# AGENTS.md

## Project Overview

php-oauth1 is a small, dependency-light OAuth 1.0 (RFC 5849) signing and verification library for PHP 8.1+. It is a
companion to `php-oidc` (OAuth 2.0 / OpenID Connect) for the older one-legged and two-legged OAuth 1.0 protocol that
integrations such as Basic LTI 1.0/1.1 still require: form-signed tool launches and, for LTI 1.1's Basic Outcomes
Service, POX/XML requests signed via the OAuth Body Hash extension (`oauth_body_hash`, all OAuth parameters forced
into the `Authorization` header). Solve the common case - signing and verifying these one-legged, no-token requests
- well, rather than chasing full three-legged OAuth 1.0 provider coverage. This is library code consumed by other
applications, not an application itself. A change here affects every consumer, so keep the public API small,
generic, and stable. Breaking changes are allowed but must be deliberate and noted, never accidental.

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

This repository is pre-implementation: there is no `composer.json`, `src/`, or `test/` yet, only `AGENTS.md` and
the reference `specs/` directory. The design below is the intended shape based on those specs, not yet-built fact -
treat it as a starting point to confirm or revise once real classes exist, not as settled architecture to match
blindly.

Expected concerns, kept separate the same way `php-oidc` separates its collaborators:

- A signature base string builder - request method, base string URI, and normalized/percent-encoded parameters
  per RFC 5849 §3.4.1, independent of which signing method consumes it.
- One signer per method (`HMAC-SHA1`, `RSA-SHA1`, `PLAINTEXT`), each small and independently testable, rather than
  one class branching on `oauth_signature_method`.
- A body-hash signer for the OAuth Body Hash extension LTI 1.1's Basic Outcomes Service requires (SHA-1 of the raw
  XML body, forcing all OAuth parameters into the `Authorization` header).
- A request verifier that recomputes a signature from an incoming request and compares it, for the Tool Provider
  side of an LTI-style integration.

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
- **Log levels.** `debug` traces the happy path. `warning` is a fail-open decision or an ambiguous runtime event,
  never a configuration choice. `alert` is reserved for a configuration choice worth a developer's own review
  (`PLAINTEXT` signing allowed outside TLS, unsigned requests accepted, nonce-replay checking disabled) - never a
  runtime event. `error` is every validation, fetch, or parse failure, always paired with the exception about to be
  thrown. Every `error()` call also carries a `security_relevant` boolean in its context, `true` only on the small
  curated set of call sites that are essentially unexplainable except as tampering or forgery, `false` everywhere
  else - `false` means "not in that curated set," never "confirmed benign." See `docs/index.html`'s Logging section
  for the full level table, the curated `true` list, and the reasoning behind it, once it exists here.
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

- `docs/index.html` is the rendered public API reference (served via GitHub Pages from `dev`), once one exists here
  - see `php-oidc`'s copy for the format to follow. Keep it in sync with any change to the public API in the same
  change, not a follow-up: a new class, interface, method, constructor parameter, `with*()` wither, enum case, or
  exception type all need a matching update there.
- It documents the public surface only. Internal collaborators (the signature base string builder, the per-method
  signers, the body-hash signer, the request verifier, and similar) are deliberately excluded - see `php-oidc`'s
  copy of the page footer for the reasoning.

## Git

- Default branch is `dev`. Treat it as the merge target for pull requests, not a branch to commit to directly.
- Keep commits focused. A commit that adds a feature and a commit that hardens/tests it are both fine as separate
  commits; do not squash a branch down to one commit by default.
