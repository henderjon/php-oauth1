<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Oauth1\Fakes\ArrayLogger;
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

	public function testForMethodLogsAnErrorForRsaSha1WithNoPublicKey(): void {
		$logger = new ArrayLogger;

		try {
			(new RequestVerifierFactory(logger: $logger))->forMethod(SignatureMethod::RsaSha1, new InMemoryCache);
			$this->fail('Expected a SigningException');
		} catch ( SigningException ) {
			$errors = $logger->recordsAt('error');
			$this->assertCount(1, $errors);
			$this->assertSame('oauth1.verifier_factory_misconfigured', $errors[0]['message']);
			$this->assertFalse($errors[0]['context']['security_relevant']);
		}
	}

}
