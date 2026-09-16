<?php

namespace Oauth1;

use PHPUnit\Framework\TestCase;

class PlaintextSignerTest extends TestCase {

	public function testSignJoinsTheEncodedSecretsWithAnAmpersand(): void {
		$credentials = new Credentials('key', 'j49sk3j29djd', 'token', 'dh893hdasih9');

		$this->assertSame('j49sk3j29djd&dh893hdasih9', (new PlaintextSigner)->sign('ignored', $credentials));
	}

	public function testSignIncludesTheAmpersandEvenWithAnEmptyTokenSecret(): void {
		$credentials = new Credentials('key', 'j49sk3j29djd');

		$this->assertSame('j49sk3j29djd&', (new PlaintextSigner)->sign('ignored', $credentials));
	}

	public function testVerifyAcceptsAMatchingSignature(): void {
		$signer      = new PlaintextSigner;
		$credentials = new Credentials('key', 'secret', 'token', 'tokensecret');

		$this->assertTrue($signer->verify('ignored', $credentials, $signer->sign('ignored', $credentials)));
	}

	public function testVerifyRejectsAMismatchedSecret(): void {
		$signer = new PlaintextSigner;

		$this->assertFalse($signer->verify(
			'ignored',
			new Credentials('key', 'secret'),
			(new PlaintextSigner)->sign('ignored', new Credentials('key', 'different')),
		));
	}

}
