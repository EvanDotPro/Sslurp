<?php
namespace SslurpTest;

use PHPUnit_Framework_TestCase as TestCase;
use Sslurp\MozillaCertData;
use DateTime;
use DateTimeZone;

class MozillaCertDataTest extends TestCase
{
    public function setUp()
    {
        $this->mozCertData = new MozillaCertData();
    }

    public function certData()
    {
        return file_get_contents(__DIR__ . '/_files/certdata.txt');
    }

    public function testContextOptionsAreSecureDefaults()
    {
        $context = $this->mozCertData->getStreamContext();
        $opts = stream_context_get_options($context);

        $this->assertSame(true, $opts['ssl']['capture_peer_cert']);
        $this->assertSame(true, $opts['ssl']['verify_peer']);
        $this->assertSame(false, $opts['ssl']['allow_self_signed']);
        $this->assertRegExp('/^.+\.(pem|crt)$/', $opts['ssl']['cafile']);
        $this->assertSame('mxr.mozilla.org', $opts['ssl']['CN_match']);
    }

    public function testCanParseVersionAndDateDataProperly()
    {
        $this->mozCertData = new MozillaCertData($this->certData());
        $dateTime = new DateTime('2012/06/28 13:50:18', new DateTimeZone('UTC'));
        $this->assertEquals($dateTime, $this->mozCertData->getDateTime());
        $this->assertSame('1.85', $this->mozCertData->getVersion());
    }

    public function testCertDataPassedToConstructorIsReturnedFromGetCertData()
    {
        $this->mozCertData = new MozillaCertData('foo');
        $this->assertEquals('foo', $this->mozCertData->getContent());
    }

    public function testExceptionThrownIfCertDataIsInvalid()
    {
        $this->setExpectedException('RuntimeException');
        $this->mozCertData = new MozillaCertData('foo');
        $this->mozCertData->getVersion();
    }

}
