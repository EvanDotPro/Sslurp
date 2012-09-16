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
        MozillaCertData::$overrideCertPin = null;
        MozillaCertData::$overrideCertExp = null;
        MozillaCertData::$forceAltCaBundle = null;
        $this->mozCertData = new MozillaCertData();
    }

    public function certData()
    {
        return file_get_contents(__DIR__ . '/_files/certdata.txt');
    }

    public function canDoOnlineTest()
    {
        if (!($fp = @stream_socket_client('tcp://mxr.mozilla.org:80', $errNo, $errStr, 1))) {
            $this->markTestSkipped('Could not reach mxr.mozilla.org for online test.');
        }
        fclose($fp);
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

    public function testExpectedCertDataReturnedFromGetContent()
    {
        $this->mozCertData = new MozillaCertData('foo');
        $this->assertEquals('foo', $this->mozCertData->getContent());
        require_once __DIR__ . '/TestAsset/MockMozillaCertDataFetchLatest.php';
        $this->mozCertData = new TestAsset\MockMozillaCertDataFetchLatest();
        $this->assertEquals('latest', $this->mozCertData->getContent());
    }

    public function testExceptionThrownIfCertDataIsInvalid()
    {
        $this->setExpectedException('RuntimeException');
        $this->mozCertData = new MozillaCertData('foo');
        $this->mozCertData->getVersion();
    }

    public function testMozillaCertDataOnlineCheck()
    {
        $this->canDoOnlineTest();
        $this->assertRegExp('/^\d+\.\d+$/', $this->mozCertData->getVersion());
    }

    public function testMozillaCertDataOnlineCheckWithInvalidPinThrowsException()
    {
        $this->canDoOnlineTest();
        MozillaCertData::$overrideCertPin = 'invalid';
        $this->setExpectedException('RuntimeException');
        $this->mozCertData->getVersion();
    }

    public function testMozillaCertDataOnlineCheckWithNewCertificateShowsWarningMessage()
    {
        $this->canDoOnlineTest();
        MozillaCertData::$overrideCertPin = 'invalid';
        MozillaCertData::$overrideCertExp = time() - 100;
        $this->setExpectedException('PHPUnit_Framework_Error_Notice');
        $this->mozCertData->getVersion();
    }

    public function testMozillaCertDataOnlineCheckWithNewCertificateStillReturnsVersion()
    {
        $this->canDoOnlineTest();
        MozillaCertData::$overrideCertPin = 'invalid';
        MozillaCertData::$overrideCertExp = time() - 100;
        $this->assertRegExp('/^\d+\.\d+$/', @$this->mozCertData->getVersion());
    }

    public function testMozillaCertDataOnlineFailsIfNoCaRootBundleFound()
    {
        $this->canDoOnlineTest();
        MozillaCertData::$forceAltCaBundle = __DIR__ . '/_files/mxr.mozilla.org.pem';
        $this->setExpectedException('RuntimeException');
        $this->mozCertData->getVersion();
    }
}
