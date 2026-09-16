<?php

namespace Oauth1;

use PHPUnit\Framework\TestCase;

class PercentEncodingTest extends TestCase {

	public function testEncodeLeavesUnreservedCharactersAlone(): void {
		$this->assertSame(
			'ABCabc123-._~',
			PercentEncoding::encode('ABCabc123-._~'),
		);
	}

	public function testEncodeUsesPercent20ForSpaceNotPlus(): void {
		$this->assertSame('r%20b', PercentEncoding::encode('r b'));
	}

	public function testEncodeUsesUppercaseHex(): void {
		$this->assertSame('%40', PercentEncoding::encode('@'));
	}

}
