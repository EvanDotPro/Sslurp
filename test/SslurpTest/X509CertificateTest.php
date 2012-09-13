<?php
namespace SslurpTest;

use PHPUnit_Framework_TestCase as TestCase;
use Sslurp\X509Certificate;

class X509CertificateTest extends TestCase
{
    public function testConsructorSupoprtsMultipleInputTypesAndCanGenerateProperKeyPin()
    {
        $certPath     = __DIR__ . '/_files/mxr.mozilla.org.pem';
        $certString   = file_get_contents($certPath);
        $certResource = openssl_x509_read($certString);
        $expectedPin  = '47cac6d8f2c2363675e6f433970f27523824d0ec';

        $cert = new X509Certificate($certPath);
        $this->assertSame($cert->getPin(), $expectedPin);

        $cert = new X509Certificate($certString);
        $this->assertSame($cert->getPin(), $expectedPin);

        $cert = new X509Certificate($certResource);
        $this->assertSame($cert->getPin(), $expectedPin);
    }
}
