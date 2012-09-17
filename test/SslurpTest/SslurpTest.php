<?php
namespace SslurpTest;

use PHPUnit_Framework_TestCase as TestCase;
use Sslurp\Sslurp;

class SslurpTest extends TestCase
{
    public function testReturnsValidSystemCaBundle()
    {
        // Check that it at least finds a CA bundle _somewhere_.
        // (not sure how this will work out on Travis)
        $caBundlePath = Sslurp::getSystemCaRootBundlePath();
        $this->assertRegExp('/^.+\.(pem|crt)$/', $caBundlePath);

        // Check that we can override it with some other valid bundle
        putenv('SSL_CERT_FILE=' . __DIR__ . '/../../data/Equifax_Secure_CA.pem');
        $caBundlePath = Sslurp::getSystemCaRootBundlePath();
        $this->assertSame(__DIR__ . '/../../data/Equifax_Secure_CA.pem', $caBundlePath);
        putenv('SSL_CERT_FILE');
    }
}
