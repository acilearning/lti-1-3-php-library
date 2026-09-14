<?php

namespace IMSGlobal\LTI\Tests;

use IMSGlobal\LTI\JWKS_Endpoint;
use phpseclib3\Crypt\RSA;
use PHPUnit\Framework\TestCase;

class JWKSEndpointTest extends TestCase {

    public function testPublicJwksIncludesModulusAndExponent(): void {
        $private = RSA::createKey(2048);
        $endpoint = new JWKS_Endpoint([
            'tool-key-1' => $private->toString('PKCS8'),
        ]);

        $jwks = $endpoint->get_public_jwks();

        $this->assertCount(1, $jwks['keys']);
        $this->assertSame('tool-key-1', $jwks['keys'][0]['kid']);
        $this->assertSame('RSA', $jwks['keys'][0]['kty']);
        $this->assertSame('RS256', $jwks['keys'][0]['alg']);
        $this->assertSame('sig', $jwks['keys'][0]['use']);
        $this->assertNotSame('', $jwks['keys'][0]['n']);
        $this->assertNotSame('', $jwks['keys'][0]['e']);
    }

    public function testUnusableKeyIsSkipped(): void {
        $endpoint = new JWKS_Endpoint([
            'bad-key' => 'not-a-private-key',
        ]);

        $jwks = $endpoint->get_public_jwks();

        $this->assertSame(['keys' => []], $jwks);
    }

}
