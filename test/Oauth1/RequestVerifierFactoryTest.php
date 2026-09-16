<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Oauth1\Fakes\InMemoryCache;
use PHPUnit\Framework\TestCase;

class RequestVerifierFactoryTest extends TestCase {

	public function testForMethodBuildsAVerifierThatAcceptsAMatchingHmacSha1Request(): void {
		$credentials = new Credentials('key', 'secret');
		$signed      = (new RequestSignerFactory)->forMethod(SignatureMethod::HmacSha1)
			->sign('POST', 'http://example.com/request', $credentials);

		(new RequestVerifierFactory)->forMethod(SignatureMethod::HmacSha1, new InMemoryCache)
			->verify('POST', 'http://example.com/request', $credentials, $signed->oauthParameters);

		$this->addToAssertionCount(1);
	}

	public function testForMethodThrowsForRsaSha1WithNoPublicKey(): void {
		$this->expectException(SigningException::class);

		(new RequestVerifierFactory)->forMethod(SignatureMethod::RsaSha1, new InMemoryCache);
	}

}
