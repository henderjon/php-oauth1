<?php

namespace Oauth1;

use PHPUnit\Framework\TestCase;

/**
 * RsaSha1Signer and RsaSha1Verifier are tested together - RSA-SHA1 is meaningless as a
 * round-trip through only one of them, since a private key signs and a public key verifies.
 */
class RsaSha1Test extends TestCase {

	/** @return array{0:string,1:string} [privateKeyPem, publicKeyPem] */
	private function generateKeyPair(): array {
		$key = openssl_pkey_new([
			'private_key_bits' => 2048,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		]);
		$this->assertNotFalse($key);

		openssl_pkey_export($key, $privateKeyPem);
		$publicKeyPem = openssl_pkey_get_details($key)['key'];

		return [ $privateKeyPem, $publicKeyPem ];
	}

	public function testVerifyAcceptsASignatureFromTheMatchingPrivateKey(): void {
		[ $privateKeyPem, $publicKeyPem ] = $this->generateKeyPair();
		$credentials = new Credentials('key');

		$signature = (new RsaSha1Signer($privateKeyPem))->sign('base string', $credentials);

		$this->assertTrue((new RsaSha1Verifier($publicKeyPem))->verify('base string', $credentials, $signature));
	}

	public function testVerifyRejectsASignatureFromADifferentKeyPair(): void {
		[ $privateKeyPem ] = $this->generateKeyPair();
		[ , $otherPublicKeyPem ] = $this->generateKeyPair();
		$credentials = new Credentials('key');

		$signature = (new RsaSha1Signer($privateKeyPem))->sign('base string', $credentials);

		$this->assertFalse((new RsaSha1Verifier($otherPublicKeyPem))->verify('base string', $credentials, $signature));
	}

	public function testVerifyRejectsATamperedBaseString(): void {
		[ $privateKeyPem, $publicKeyPem ] = $this->generateKeyPair();
		$credentials = new Credentials('key');

		$signature = (new RsaSha1Signer($privateKeyPem))->sign('base string', $credentials);

		$this->assertFalse((new RsaSha1Verifier($publicKeyPem))->verify('a different base string', $credentials, $signature));
	}

	public function testMethodIsRsaSha1ForBothSignerAndVerifier(): void {
		[ $privateKeyPem, $publicKeyPem ] = $this->generateKeyPair();

		$this->assertSame(SignatureMethod::RsaSha1, (new RsaSha1Signer($privateKeyPem))->method());
		$this->assertSame(SignatureMethod::RsaSha1, (new RsaSha1Verifier($publicKeyPem))->method());
	}

}
