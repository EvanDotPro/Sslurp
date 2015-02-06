<?php
namespace SslurpTest;

use PHPUnit_Framework_TestCase as TestCase;
//use Sslurp\MozillaCertData;
use DateTime;
use DateTimeZone;
use SslurpTest\TestAsset\MockMozillaCertData as MozillaCertData;
use SslurpTest\TestAsset\MockMozillaCertDataInvalidPin as MozillaCertDataInvalidPin;
use SslurpTest\TestAsset\MockMozillaCertDataInvalidPinAndExp as MozillaCertDataInvalidPinAndExp;

class MozillaCertDataTest extends TestCase
{
    public function setUp()
    {
        $this->mozCertData = new MozillaCertData();
    }

    public function tearDown()
    {
        putenv('SSL_CERT_FILE');
        MozillaCertData::$allowOnlineTest = false;
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
        MozillaCertData::$allowOnlineTest = true;
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
        $this->assertSame('mxr.mozilla.org', $opts['ssl'][$this->mozCertData->getPeerNameOption()]);
    }

    public function testCanParseVersionAndDateDataProperly()
    {
        $dateTime = new DateTime('2012/06/28 13:50:18', new DateTimeZone('UTC'));
        $this->assertEquals($dateTime, $this->mozCertData->getDateTime());
        $this->assertSame('1.85', $this->mozCertData->getVersion());
    }

    public function testExpectedCertDataReturnedFromGetContent()
    {
        $this->assertEquals($this->certData(), $this->mozCertData->getContent());
    }

    public function testExceptionThrownIfCertDataIsInvalidWhenFetchingVersion()
    {
        $this->setExpectedException('RuntimeException');
        $this->mozCertData->setCertData('foo');
        $this->mozCertData->getVersion();
    }

    public function testExceptionThrownIfCertDataIsInvalidWhenFetchingDateTime()
    {
        $this->setExpectedException('RuntimeException');
        $this->mozCertData->setCertData('foo');
        $this->mozCertData->getDateTime();
    }

    public function testMozillaCertDataOnlineCheck()
    {
        $this->canDoOnlineTest();
        $this->assertRegExp('/^\d+\.\d+$/', $this->mozCertData->getVersion());
    }

    public function testMozillaCertDataOnlineCheckWithInvalidPinThrowsException()
    {
        $this->canDoOnlineTest();
        $this->mozCertData = new MozillaCertDataInvalidPin;
        $this->setExpectedException('RuntimeException');
        $this->mozCertData->getVersion();
    }

    public function testMozillaCertDataOnlineCheckWithNewCertificateShowsWarningMessage()
    {
        $this->canDoOnlineTest();
        $this->mozCertData = new MozillaCertDataInvalidPinAndExp;
        $this->setExpectedException('PHPUnit_Framework_Error_Notice');
        $this->mozCertData->getVersion();
    }

    public function testMozillaCertDataOnlineCheckWithNewCertificateStillReturnsVersion()
    {
        $this->canDoOnlineTest();
        $this->mozCertData = new MozillaCertDataInvalidPinAndExp;
        $this->assertRegExp('/^\d+\.\d+$/', @$this->mozCertData->getVersion());
    }

    public function testMozillaCertDataOnlineFailsIfNoCaRootBundleFound()
    {
        $this->canDoOnlineTest();
        putenv('SSL_CERT_FILE=' . __DIR__ . '/_files/mxr.mozilla.org.pem');
        $this->setExpectedException('RuntimeException');
        $this->mozCertData->getVersion();
    }
}
