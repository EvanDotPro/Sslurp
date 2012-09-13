<?php
namespace SslurpTest;

use Sslurp\RootCaBundleBuilder;
use PHPUnit_Framework_TestCase as TestCase;

class RootCaBundleBuilderTest extends TestCase
{
    const EXPECTED_HASH = '15202a7c9c4cf9da5920d6c557f6614c9e9b7f308f76c610028ab4ea69ffb230';

    /**
     * @TODO: Make RootCaBundleBuilder more testable
     */
    public function testBuildsRootCaBundleProperly()
    {
        define('SSLURP_OVERRIDE_DATETIME', 'testing');
        $rawCertData = file_get_contents(__DIR__ . '/_files/certdata.txt');
        $builder     = new RootCaBundleBuilder();
        $result      = $builder->getUpdatedRootCaBundle($rawCertData);
        $this->assertSame(static::EXPECTED_HASH, hash('sha256', $result));
    }
}
