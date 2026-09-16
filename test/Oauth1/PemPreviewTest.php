<?php

namespace Oauth1;

use PHPUnit\Framework\TestCase;

class PemPreviewTest extends TestCase {

	public function testFindsAPrivateKeyHeaderAndFooter(): void {
		$this->assertSame(
			'-----BEGIN RSA PRIVATE KEY-----',
			PemPreview::describe("-----BEGIN RSA PRIVATE KEY-----\nMIIB...redacted...\n-----END RSA PRIVATE KEY-----\n"),
		);
	}

	public function testFindsAPublicKeyHeaderAndFooter(): void {
		$this->assertSame(
			'-----BEGIN PUBLIC KEY-----',
			PemPreview::describe("-----BEGIN PUBLIC KEY-----\nMIIB...redacted...\n-----END PUBLIC KEY-----\n"),
		);
	}

	public function testReportsAnEmptyValueDistinctlyFromGarbage(): void {
		$this->assertSame('(empty)', PemPreview::describe(''));
	}

	public function testReportsGarbageAsNoHeaderFound(): void {
		$this->assertSame('(no PEM header found)', PemPreview::describe('not a real key'));
	}

	/**
	 * The header alone gives no signal here - truncating from the end always leaves the
	 * header (line one) fully intact. This is the whole reason describe() also checks for the
	 * matching footer: a key cut off partway through is the single most common real failure
	 * this class exists for, confirmed directly against openssl_pkey_get_private() actually
	 * rejecting a truncated key.
	 */
	public function testFlagsAMissingFooterAsLikelyTruncation(): void {
		$truncated = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...redacted, cut off partway through";

		$this->assertSame(
			'-----BEGIN RSA PRIVATE KEY----- (footer missing - likely truncated)',
			PemPreview::describe($truncated),
		);
	}

	public function testDoesNotFlagTruncationWhenTheFooterIsPresent(): void {
		$complete = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...redacted...\n-----END RSA PRIVATE KEY-----\n";

		$this->assertStringNotContainsString('truncated', PemPreview::describe($complete));
	}

	public function testRequiresTheFooterToMatchTheSameKeyTypeAsTheHeader(): void {
		// A PUBLIC KEY footer does not satisfy a PRIVATE KEY header - this is not just "some
		// END line exists somewhere," it is specifically the matching one.
		$mismatched = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...redacted...\n-----END PUBLIC KEY-----\n";

		$this->assertSame(
			'-----BEGIN RSA PRIVATE KEY----- (footer missing - likely truncated)',
			PemPreview::describe($mismatched),
		);
	}

	public function testNeverRevealsAnyOfTheKeyMaterialAfterTheHeaderLine(): void {
		$preview = PemPreview::describe("-----BEGIN RSA PRIVATE KEY-----\nSECRETBYTESHERE\n-----END RSA PRIVATE KEY-----\n");

		$this->assertStringNotContainsString('SECRETBYTESHERE', $preview);
	}

}
