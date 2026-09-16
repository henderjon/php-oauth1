<?php

namespace Oauth1;

use PHPUnit\Framework\TestCase;

class CredentialsTest extends TestCase {

	private function credentials(): Credentials {
		return new Credentials('key', 'secret', 'token', 'tokensecret');
	}

	public function testWithConsumerKeyChangesOnlyConsumerKey(): void {
		$changed = $this->credentials()->withConsumerKey('newkey');

		$this->assertSame('newkey', $changed->consumerKey);
		$this->assertSame('secret', $changed->consumerSecret);
		$this->assertSame('token', $changed->token);
		$this->assertSame('tokensecret', $changed->tokenSecret);
	}

	public function testWithConsumerSecretChangesOnlyConsumerSecret(): void {
		$changed = $this->credentials()->withConsumerSecret('newsecret');

		$this->assertSame('key', $changed->consumerKey);
		$this->assertSame('newsecret', $changed->consumerSecret);
		$this->assertSame('token', $changed->token);
		$this->assertSame('tokensecret', $changed->tokenSecret);
	}

	public function testWithTokenChangesOnlyToken(): void {
		$changed = $this->credentials()->withToken('newtoken');

		$this->assertSame('key', $changed->consumerKey);
		$this->assertSame('secret', $changed->consumerSecret);
		$this->assertSame('newtoken', $changed->token);
		$this->assertSame('tokensecret', $changed->tokenSecret);
	}

	public function testWithTokenSecretChangesOnlyTokenSecret(): void {
		$changed = $this->credentials()->withTokenSecret('newtokensecret');

		$this->assertSame('key', $changed->consumerKey);
		$this->assertSame('secret', $changed->consumerSecret);
		$this->assertSame('token', $changed->token);
		$this->assertSame('newtokensecret', $changed->tokenSecret);
	}

	public function testDefaultsAreEmptyStrings(): void {
		$credentials = new Credentials('key');

		$this->assertSame('', $credentials->consumerSecret);
		$this->assertSame('', $credentials->token);
		$this->assertSame('', $credentials->tokenSecret);
	}

}
