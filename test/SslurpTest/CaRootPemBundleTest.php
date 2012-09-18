<?php
namespace SslurpTest;

use PHPUnit_Framework_TestCase as TestCase;
use SslurpTest\TestAsset\MockMozillaCertData as MozillaCertData;
use SslurpTest\TestAsset\MockCaRootPemBundle as CaRootPemBundle;
use DateTime;
use DateTimeZone;

class CaRootPemBundleTest extends TestCase
{
    public function setUp($newVersion = false)
    {
        $this->bundle = new CaRootPemBundle(__DIR__ . '/_files/ca-bundle.pem', new MozillaCertData);
    }

    public function testBuildsCaRootBundleProperly()
    {
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
        $this->bundle = new CaRootPemBundle(__DIR__ . '/_files/ca-bundle.pem', new MozillaCertData);
        $this->bundle->setPemContent(str_replace('1.85', '1.86', $this->bundle->getContent()));
        $this->assertFalse($this->bundle->isLatest());
    }

    public function testWillFetchMozillaCertData()
    {
        $this->assertNotNull($this->bundle->getContent());
        $this->assertInstanceOf('Sslurp\MozillaCertData', $this->bundle->getMozillaCertData());
    }

    public function testWillCreateBundleFileIfItDoesNotExist()
    {
        $file = sys_get_temp_dir() . '/ca-bundle.pem';
        $this->assertFileNotExists($file);
        $this->bundle = new CaRootPemBundle($file, new MozillaCertData);
        $this->assertFileExists($file);
    }
}
