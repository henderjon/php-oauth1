<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Oauth1\Fakes\ArrayLogger;
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

	public function testSignLogsADebugTraceOnSuccess(): void {
		[ $privateKeyPem ] = $this->generateKeyPair();
		$logger = new ArrayLogger;

		(new RsaSha1Signer($privateKeyPem, logger: $logger))->sign('base string', new Credentials('key'));

		$debug = $logger->recordsAt('debug');
		$this->assertCount(1, $debug);
		$this->assertSame('oauth1.rsa_sha1_signed', $debug[0]['message']);
		$this->assertSame([], $logger->recordsAboveDebug());
	}

	public function testSignLogsAnErrorAndThrowsForAnUnreadablePrivateKey(): void {
		$logger = new ArrayLogger;

		try {
			(new RsaSha1Signer('not a real key', logger: $logger))->sign('base string', new Credentials('key'));
			$this->fail('Expected a SigningException');
		} catch ( SigningException $exception ) {
			$errors = $logger->recordsAt('error');
			$this->assertCount(1, $errors);
			$this->assertSame('oauth1.signing_failed', $errors[0]['message']);
			$this->assertSame('key', $errors[0]['context']['consumer_key']);
			$this->assertFalse($errors[0]['context']['security_relevant']);
			$this->assertSame('key', $exception->getConsumerKey());
			$this->assertSame('(no PEM header found)', $errors[0]['context']['private_key_pem']);
		}
	}

	public function testSignLogsAFooterMissingHintForATruncatedPrivateKey(): void {
		[ $privateKeyPem ] = $this->generateKeyPair();
		$truncated = substr($privateKeyPem, 0, (int) (strlen($privateKeyPem) / 2));
		$logger    = new ArrayLogger;

		try {
			(new RsaSha1Signer($truncated, logger: $logger))->sign('base string', new Credentials('key'));
			$this->fail('Expected a SigningException');
		} catch ( SigningException ) {
			$errors = $logger->recordsAt('error');
			$this->assertStringContainsString('footer missing - likely truncated', $errors[0]['context']['private_key_pem']);
		}
	}

	public function testVerifyLogsADebugTraceOnceTheKeyIsLoaded(): void {
		[ , $publicKeyPem ] = $this->generateKeyPair();
		$logger = new ArrayLogger;

		(new RsaSha1Verifier($publicKeyPem, $logger))->verify('base string', new Credentials('key'), 'not-a-real-signature');

		$debug = $logger->recordsAt('debug');
		$this->assertCount(1, $debug);
		$this->assertSame('oauth1.rsa_sha1_key_loaded', $debug[0]['message']);
		$this->assertSame([], $logger->recordsAboveDebug());
	}

	public function testVerifyLogsAnErrorAndThrowsForAnUnreadablePublicKey(): void {
		$logger = new ArrayLogger;

		try {
			(new RsaSha1Verifier('not a real key', $logger))->verify('base string', new Credentials('key'), 'signature');
			$this->fail('Expected a SigningException');
		} catch ( SigningException $exception ) {
			$errors = $logger->recordsAt('error');
			$this->assertCount(1, $errors);
			$this->assertSame('oauth1.verifying_failed', $errors[0]['message']);
			$this->assertFalse($errors[0]['context']['security_relevant']);
			$this->assertSame('key', $exception->getConsumerKey());
			$this->assertSame('(no PEM header found)', $errors[0]['context']['public_key_pem']);
		}
	}

	public function testVerifyLogsAFooterMissingHintForATruncatedPublicKey(): void {
		[ , $publicKeyPem ] = $this->generateKeyPair();
		$truncated = substr($publicKeyPem, 0, (int) (strlen($publicKeyPem) / 2));
		$logger    = new ArrayLogger;

		try {
			(new RsaSha1Verifier($truncated, $logger))->verify('base string', new Credentials('key'), 'signature');
			$this->fail('Expected a SigningException');
		} catch ( SigningException ) {
			$errors = $logger->recordsAt('error');
			$this->assertStringContainsString('footer missing - likely truncated', $errors[0]['context']['public_key_pem']);
		}
	}

	/**
	 * $privateKey/$publicKey are the key's own PEM content, not a path to one - a bare filename
	 * (no scheme) is not treated as a path at all, and fails exactly like any other unreadable
	 * key, empirically confirmed against PHP's own openssl_pkey_get_private()/
	 * openssl_pkey_get_public() rather than assumed.
	 */
	public function testABareFilenameIsNotAcceptedAsAPathToTheKey(): void {
		$tempFile = tempnam(sys_get_temp_dir(), 'rsa_test_key_');
		[ $privateKeyPem, $publicKeyPem ] = $this->generateKeyPair();
		file_put_contents($tempFile, $privateKeyPem);

		try {
			$this->expectException(SigningException::class);

			(new RsaSha1Signer($tempFile))->sign('base string', new Credentials('key'));
		} finally {
			unlink($tempFile);
		}
	}

	public function testAFileSchemePrefixedPathIsAcceptedAsAnIncidentalConsequenceOfOpensslsOwnStreamWrapperSupport(): void {
		$tempFile = tempnam(sys_get_temp_dir(), 'rsa_test_key_');
		[ $privateKeyPem, $publicKeyPem ] = $this->generateKeyPair();
		file_put_contents($tempFile, $privateKeyPem);

		try {
			$signature = (new RsaSha1Signer("file://$tempFile"))->sign('base string', new Credentials('key'));

			$this->assertTrue((new RsaSha1Verifier($publicKeyPem))->verify('base string', new Credentials('key'), $signature));
		} finally {
			unlink($tempFile);
		}
	}

}
