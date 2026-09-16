<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use PHPUnit\Framework\TestCase;

class RequestSignerFactoryTest extends TestCase {

	private function rsaPrivateKeyPem(): string {
		$key = openssl_pkey_new([ 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ]);
		openssl_pkey_export($key, $pem);

		return $pem;
	}

	public function testForMethodBuildsAHmacSha1Signer(): void {
		$signed = (new RequestSignerFactory)->forMethod(SignatureMethod::HmacSha1)
			->sign('POST', 'http://example.com/request', new Credentials('key', 'secret'));

		$this->assertSame('HMAC-SHA1', $signed->oauthParameters['oauth_signature_method']);
	}

	public function testForMethodBuildsAPlaintextSigner(): void {
		$signed = (new RequestSignerFactory)->forMethod(SignatureMethod::Plaintext)
			->sign('POST', 'http://example.com/request', new Credentials('key', 'secret'));

		$this->assertSame('PLAINTEXT', $signed->oauthParameters['oauth_signature_method']);
	}

	public function testForMethodBuildsAnRsaSha1SignerWhenGivenAPrivateKey(): void {
		$signed = (new RequestSignerFactory)->forMethod(SignatureMethod::RsaSha1, $this->rsaPrivateKeyPem())
			->sign('POST', 'http://example.com/request', new Credentials('key'));

		$this->assertSame('RSA-SHA1', $signed->oauthParameters['oauth_signature_method']);
	}

	public function testForMethodThrowsForRsaSha1WithNoPrivateKey(): void {
		$this->expectException(SigningException::class);

		(new RequestSignerFactory)->forMethod(SignatureMethod::RsaSha1);
	}

}
