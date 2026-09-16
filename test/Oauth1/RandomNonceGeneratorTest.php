<?php

namespace Oauth1;

use PHPUnit\Framework\TestCase;

class RandomNonceGeneratorTest extends TestCase {

	public function testGenerateProducesA32CharacterHexString(): void {
		$nonce = (new RandomNonceGenerator)->generate();

		$this->assertSame(32, strlen($nonce));
		$this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $nonce);
	}

	public function testGenerateIsRandomEachCall(): void {
		$generator = new RandomNonceGenerator;

		$this->assertNotSame($generator->generate(), $generator->generate());
	}

}
