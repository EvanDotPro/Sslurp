<?php
namespace SslurpTest;

use PHPUnit_Framework_TestCase as TestCase;
use Sslurp\CaRootPemBundle;
use Sslurp\MozillaCertData;
use DateTime;
use DateTimeZone;

class CaRootPemBundleTest extends TestCase
{
    public function setUp($newVersion = false)
    {
        $pemBundle = file_get_contents(__DIR__ . '/_files/ca-bundle.pem');
        $certData  = file_get_contents(__DIR__ . '/_files/certdata.txt');
        if ($newVersion) $certData = str_replace('1.85', '1.86', $certData);
        CaRootPemBundle::$overrideDateTime = null;
        $this->bundle = new CaRootPemBundle($pemBundle, new MozillaCertData($certData));
    }

    public function testBuildsCaRootBundleProperly()
    {
        CaRootPemBundle::$overrideDateTime = 'for testing';
        $result = $this->bundle->getUpdatedCaRootBundle();
        $this->assertStringEqualsFile(__DIR__ . '/_files/ca-bundle.pem', $result);
    }

    public function testCanParseVersionAndDateDataProperly()
    {
        $dateTime = new DateTime('2012/06/28 13:50:18', new DateTimeZone('UTC'));
        $this->assertEquals($dateTime, $this->bundle->getDateTime());
        $this->assertSame('1.85', $this->bundle->getVersion());
    }

    public function testIsLatestMethodWorks()
    {
        $this->assertTrue($this->bundle->isLatest());
        $this->setUp(true);
        $this->assertFalse($this->bundle->isLatest());
    }

    public function testWillFetchMozillaCertData()
    {
        require_once __DIR__ . '/TestAsset/MockMozillaCertData.php';
        $bundle = new CaRootPemBundle(null, new TestAsset\MockMozillaCertData);
        $this->assertNotNull($bundle->getContent());
    }
}
