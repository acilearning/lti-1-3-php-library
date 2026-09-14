<?php
namespace IMSGlobal\LTI;

use phpseclib3\Crypt\PublicKeyLoader;

class JWKS_Endpoint {

    private $keys;

    public function __construct(array $keys) {
        $this->keys = $keys;
    }

    public static function new($keys) {
        return new JWKS_Endpoint($keys);
    }

    public static function from_issuer(Database $database, $issuer) {
        $registration = $database->find_registration_by_issuer($issuer);
        return new JWKS_Endpoint([$registration->get_kid() => $registration->get_tool_private_key()]);
    }

    public static function from_registration(LTI_Registration $registration) {
        return new JWKS_Endpoint([$registration->get_kid() => $registration->get_tool_private_key()]);
    }

    public function get_public_jwks() {
        $jwks = [];
        foreach ($this->keys as $kid => $private_key) {
            $jwk = $this->public_jwk($private_key);
            if ($jwk === null) {
                continue;
            }
            $jwks[] = array(
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'e' => $jwk['e'],
                'n' => $jwk['n'],
                'kid' => (string) $kid,
            );
        }
        return ['keys' => $jwks];
    }

    public function output_jwks() {
        echo json_encode($this->get_public_jwks());
    }

    private function public_jwk($private_key) {
        try {
            $key = PublicKeyLoader::load($private_key);
            if (method_exists($key, 'getPublicKey')) {
                $key = $key->getPublicKey();
            }
            $decoded = json_decode($key->toString('JWK'), true);
        }
        catch (\Throwable $e) {
            return null;
        }
        $jwk = is_array($decoded) && isset($decoded['keys'][0]) && is_array($decoded['keys'][0])
            ? $decoded['keys'][0]
            : $decoded;
        if (!is_array($jwk) || empty($jwk['n']) || empty($jwk['e'])) {
            return null;
        }
        return $jwk;
    }

}
