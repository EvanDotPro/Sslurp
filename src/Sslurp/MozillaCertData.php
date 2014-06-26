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
    // mxr.mozilla.org cert expires Mar 25th, 2015
    const MOZILLA_MXR_SSL_PIN = 'b4e6e7a3d911b5a09a9835f525122acfa1442a3b';
    const MOZILLA_MXR_SSL_EXP = 1425186000; // Mar 1st, 2015

    /**
     * certdata.txt contents
     *
     * @var string
     */
    protected $certData = null;

    /**
     * Stream context
     *
     * @var resource
     */
    protected $context = null;

    /**
     * Get the raw certdata.txt contents from mxr.mozilla.org
     *
     * @return string
     */
    public function getContent($until = false)
    {
        if ($until) {
            // don't cache the partial fetch for version check
            if ($this->certData !== null) {
                return substr($this->certData, 0, strpos($this->certData, "\n", strpos($this->certData, $until)));
            }

            return $this->fetchLatestCertData($until);
        }

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
        if (!$this->context) {
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

    protected function fetchLatestCertData($until = false)
    {
        $ctx = $this->getStreamContext();

        set_error_handler(function ($code, $message, $filename, $lineno, $context) {
            throw new \ErrorException(sprintf('%s: %s in %s line %d', $code, $message, $filename, $lineno), $code, 0, $filename, $lineno);
        });

        try {
            $fp = stream_socket_client('ssl://mxr.mozilla.org:443', $errNo, $errStr, 30, STREAM_CLIENT_CONNECT, $ctx);
        } catch (\ErrorException $e) {
            restore_error_handler();
            throw new \RuntimeException($errStr, $errNo, $e);
        }

        restore_error_handler();

        $headers  = "GET /mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1 HTTP/1.1\r\n";
        $headers .= "Host: mxr.mozilla.org\r\n";
        $headers .= "Connection: close\r\n";
        $headers .= "Accept: */*\r\n";
        fwrite($fp, "{$headers}\r\n"); // send request

        $response = '';
        while (!feof($fp)) {
            $response .= fgets($fp);
            if ($until && strpos($response, $until) !== false) {
                break;
            }
        }
        fclose($fp);

        $params = stream_context_get_params($ctx);
        $cert   = new X509Certificate($params['options']['ssl']['peer_certificate']);
        $pin    = $cert->getPin();

        if ($pin !== static::MOZILLA_MXR_SSL_PIN) {
            if (time() < static::MOZILLA_MXR_SSL_EXP) {
                throw new \RuntimeException(sprintf(
                   'ERROR: Certificate pin for mxr.mozilla.org did NOT match expected value! ' .
                   'Expected: %s Received: %s', static::MOZILLA_MXR_SSL_PIN, $pin
                ));
            }
            trigger_error('WARNING: mxr.mozilla.org certificate pin may be out of date. ' .
                'If you continue to see this message after updating Sslurp, please ' .
                'file an issue at https://github.com/EvanDotPro/Sslurp/issues');
        }

        return $this->decodeChunkedString($this->getResponseBody($response));
    }

    protected function decodeChunkedString($string)
    {
        $result       = '';
        $currentPos   = 0;
        $stringLength = strlen($string);

        while ($currentPos < $stringLength) {
            $position    = strpos($string, "\r\n", $currentPos);
            $length      = hexdec(substr($string, $currentPos, $position - $currentPos));
            $result     .= substr($string, $position + 2, $length);
            $currentPos  = $position + 2;
        }

        return $result;
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
        return Sslurp::getSystemCaRootBundlePath() ?: __DIR__ . '/../../data/Equifax_Secure_Ca.pem';
    }
}
