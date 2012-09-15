<?php
/**
 * This file is part of Sslurp.
 * https://github.com/EvanDotPro/Sslurp
 *
 * (c) Evan Coury <me@evancoury.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Sslurp;

class MozillaCertData extends AbstractCaRootData
{
    // mxr.mozilla.org cert expires Nov 28th, 2013
    const MOZILLA_MXR_SSL_PIN = '47cac6d8f2c2363675e6f433970f27523824d0ec';

    /**
     * certdata.txt contents
     *
     * @var string
     */
    private $certData = null;

    /**
     * Stream context
     *
     * @var resource
     */
    private $context = null;

    /**
     * @param string $certData Used for unit testing
     */
    public function __construct($certData = null)
    {
        $this->certData = $certData;
    }

    /**
     * Get the raw certdata.txt contents from mxr.mozilla.org
     *
     * @return string
     */
    public function getContent()
    {
        if ($this->certData === null) {
            $this->certData = $this->fetchLatestCertData();
        }

        return $this->certData;
    }

    /**
     * Get the stream context for the TCP connection to the server.
     *
     * If no stream context is set, will create a default one.
     *
     * @return resource
     */
    public function getStreamContext()
    {
        if (! $this->context) {
            $this->context = stream_context_create(array('ssl' => array(
                'capture_peer_cert' => true,
                'verify_peer'       => true,
                'allow_self_signed' => false,
                'cafile'            => $this->getRootCaBundlePath(),
                'CN_match'          => 'mxr.mozilla.org',
            )));
        }

        return $this->context;
    }

    protected function fetchLatestCertData()
    {
        $ctx = $this->getStreamContext();

        $fp = stream_socket_client('ssl://mxr.mozilla.org:443', $errNo, $errStr, 30, STREAM_CLIENT_CONNECT, $ctx);

        if (!$fp) {
            throw new \RuntimeException($errStr, $errNo);
        }

        $headers  = "GET /mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1 HTTP/1.1\r\n";
        $headers .= "Host: mxr.mozilla.org\r\n";
        $headers .= "Connection: close\r\n";
        $headers .= "Accept: */*\r\n";
        fwrite($fp, "{$headers}\r\n"); // send request

        $response = '';
        while (!feof($fp)) {
            $response .= fgets($fp);
        }
        fclose($fp);

        $params = stream_context_get_params($ctx);
        $cert   = new X509Certificate($params['options']['ssl']['peer_certificate']);
        $pin    = $cert->getPin();

        if ($pin !== static::MOZILLA_MXR_SSL_PIN) {
            if (time() > 1383282000) { // If it's November 1st, 2013 or later (mxr.mozilla.org cert expires Nov 28th, 2013)
                echo "WARNING: mxr.mozilla.org certificate pin may be out of date. " .
                     "If you see this, message, please file an issue at https://github.com/EvanDotPro/Sslurp/issues\n";
            } else {
                echo "ERROR: Certificate pin for mxr.mozilla.org did NOT match expected value!\n\n";
                echo 'Expected: ' . static::MOZILLA_MXR_SSL_PIN . "\n";
                echo "Received: {$pin}\n";
                exit(1);
            }
        }

        return $this->getResponseBody($response);
    }

    protected function getResponseBody($string)
    {
        $lines = explode("\r\n", $string);

        $isHeader = true;
        $headers = $content = array();

        while ($lines) {
            $nextLine = array_shift($lines);

            if ($isHeader && $nextLine == '') {
                $isHeader = false;
                continue;
            }
            if ($isHeader) {
                $headers[] = $nextLine;
            } else {
                $content[] = $nextLine;
            }
        }

        return implode("\r\n", $content);
    }

    protected function getRootCaBundlePath()
    {
        $caBundlePaths = array(
            '/etc/pki/tls/certs/ca-bundle.crt',
            '/etc/ssl/certs/ca-certificates.crt',
            '/etc/ssl/ca-bundle.pem',
            '/usr/share/ssl/certs/ca-bundle.crt',
            __DIR__ . '/../../data/Equifax_Secure_Ca.pem',
        );

        foreach ($caBundlePaths as $caBundle) {
            if (is_readable($caBundle)) {
                break;
            }
        }

        return $caBundle;
    }
}
