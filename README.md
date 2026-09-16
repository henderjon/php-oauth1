# php-oauth1

[![CI](https://github.com/henderjon/php-oauth1/actions/workflows/ci.yml/badge.svg)](https://github.com/henderjon/php-oauth1/actions/workflows/ci.yml)

## reason

Most remaining uses of OAuth 1.0 are not a full three-legged authorization dance against a public API - they are
a fixed pair of parties (a Learning Management System and a tool, most often) signing one-legged, no-token
requests to prove who sent them. This library targets that case well, rather than chasing every OAuth 1.0
provider's own quirks.

## scope

This library implements OAuth 1.0 (RFC 5849) request signing and verification, on both sides of a request: the
signer role (building `oauth_*` parameters and a signature for an outgoing request) and the verifier role
(recomputing a signature from an incoming request and comparing it, with timestamp-window and nonce-replay
checks). A companion namespace, `BasicLti1`, layers Basic LTI 1.0/1.1 tool-launch construction and verification on
top of the OAuth 1.0 core - see its own scope note for what it does and does not cover yet.

## installation

Install the package with Composer:

```sh
composer require henderjon/php-oauth1
```

See the [example harness](example/README.md) for a full Basic LTI 1.0 launch running over real HTTP between two apps, or the
[API documentation](https://henderjon.github.io/php-oauth1/) for the full public API reference (docs/).

See also: [packagist](https://packagist.org/packages/henderjon/php-oauth1).
