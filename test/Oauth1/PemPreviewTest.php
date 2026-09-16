<?php

namespace Oauth1;

use PHPUnit\Framework\TestCase;

class PemPreviewTest extends TestCase {

	public function testFindsAPrivateKeyHeader(): void {
		$this->assertSame(
			'-----BEGIN RSA PRIVATE KEY-----',
			PemPreview::headerLine("-----BEGIN RSA PRIVATE KEY-----\nMIIB...redacted...\n-----END RSA PRIVATE KEY-----\n"),
		);
	}

	public function testFindsAPublicKeyHeader(): void {
		$this->assertSame(
			'-----BEGIN PUBLIC KEY-----',
			PemPreview::headerLine("-----BEGIN PUBLIC KEY-----\nMIIB...redacted...\n-----END PUBLIC KEY-----\n"),
		);
	}

	public function testReportsAnEmptyValueDistinctlyFromGarbage(): void {
		$this->assertSame('(empty)', PemPreview::headerLine(''));
	}

	public function testReportsGarbageAsNoHeaderFound(): void {
		$this->assertSame('(no PEM header found)', PemPreview::headerLine('not a real key'));
	}

	public function testNeverRevealsAnyOfTheKeyMaterialAfterTheHeaderLine(): void {
		$preview = PemPreview::headerLine("-----BEGIN RSA PRIVATE KEY-----\nSECRETBYTESHERE\n-----END RSA PRIVATE KEY-----\n");

		$this->assertStringNotContainsString('SECRETBYTESHERE', $preview);
	}

}
