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

class RootCaBundleBuilder
{
    public function __construct()
    {
        if (!extension_loaded('openssl')) {
            echo "ERROR: This script requires PHP with openssl support.\n";
            exit(1);
        }
    }

    public function updateRootCaBundle($expectedFingerprint, $outputFile = false)
    {
        $rawBundle = $this->getLatestRawCaBundle($expectedFingerprint);
        $caBundle = $this->getLatestPemCaBundle($rawBundle);
        if ($outputFile) {
            file_put_contents($outputFile, $caBundle);
            return true;
        }
        return $caBundle;
    }

    protected function getSha1Fingerprint($certificate)
    {
        $certificate = str_replace('-----BEGIN CERTIFICATE-----', '', $certificate);
        $certificate = str_replace('-----END CERTIFICATE-----', '', $certificate);
        $certificate = base64_decode($certificate);
        $fingerprint = strtoupper(sha1($certificate));
        $fingerprint = str_split($fingerprint, 2);
        return implode(':', $fingerprint);
    }

    protected function getLatestPemCaBundle($rawCaBundle)
    {
        $rawCertData = explode("\n", $rawCaBundle);
        $currentDate = date(DATE_RFC822);
        $caBundle = <<<EOT
##
## Bundle of CA Root Certificates
##
## Generated at $currentDate
## Generated with Sslurp (https://github.com/EvanDotPro/Sslurp)
##
## This is a bundle of X.509 certificates of public Certificate Authorities
## (CA). These were automatically extracted from Mozilla's root certificates
## file (certdata.txt).  This file can be found in the mozilla source tree:
## '/mozilla/security/nss/lib/ckfw/builtins/certdata.txt'
##
## It contains the certificates in PEM format and therefore
## can be directly used with curl / libcurl / php_curl, or with
## an Apache+mod_ssl webserver for SSL client authentication.
## Just configure this file as the SSLCACertificateFile.
##


EOT;
        $caname = '';
        while (($line = array_shift($rawCertData)) !== null) {
            if (preg_match('/\*\*\*\*\* BEGIN LICENSE BLOCK \*\*\*\*\*/', $line)) {
                $caBundle .= $line;
                while (($line = array_shift($rawCertData)) !== null) {
                    $caBundle .= $line;
                    if (preg_match('/\*\*\*\*\* END LICENSE BLOCK \*\*\*\*\*/', $line)) break;
                }
            }
            if (preg_match('/^#|^\s*$/', $line)) continue;
            $line = rtrim($line);
            if (preg_match('/^CVS_ID\s+\"(.*)\"/', $line, $match)) {
                $caBundle .= "# $match[1]\n";
            }
            if (preg_match('/^CKA_LABEL\s+[A-Z0-9]+\s+\"(.*)\"/', $line, $match)) {
                $caname = $match[1];
            }
            if (preg_match('/^CKA_VALUE MULTILINE_OCTAL/', $line)) {
                $data = '';
                while ($line = array_shift($rawCertData)) {
                    if (preg_match('/^END/', $line)) break;
                    $line = rtrim($line);
                    $octets = explode('\\', $line);
                    array_shift($octets);
                    foreach ($octets as $oct) {
                        $data .= chr(octdec($oct));
                    }
                }
                $pem = "-----BEGIN CERTIFICATE-----\n"
                     . chunk_split(base64_encode($data), 76, "\n")
                     . "-----END CERTIFICATE-----\n";
                $caBundle .= "\n$caname\n";
                $caBundle .= str_repeat('=', strlen($caname))."\n";
                $caBundle .= $pem;
            }
        }
        return $caBundle;
    }

    protected function getLatestRawCaBundle($expectedFingerprint = false)
    {
        $ctx = stream_context_create(array('ssl' => array(
            'capture_peer_cert' => true,
            'verify_peer'       => false,
            'allow_self_signed' => false,
            //'cafile'            => '/etc/pki/tls/certs/ca-bundle.crt',
            'CN_match'          => 'mxr.mozilla.org',
        )));
        $fp = stream_socket_client('ssl://mxr.mozilla.org:443', $errNo, $errStr, 30, STREAM_CLIENT_CONNECT, $ctx);
        if (!$fp) throw new \RuntimeException($errStr, $errorNo);
        $headers  = "GET /mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1 HTTP/1.1\r\n";
        $headers .= "Host: mxr.mozilla.org\r\n";
        $headers .= "Connection: close\r\n";
        $headers .= "Accept: */*\r\n";
        fwrite($fp, "{$headers}\r\n");
        $response = '';
        while (!feof($fp)) {
            $response .= fgets($fp);
        }
        fclose($fp);
        if ($expectedFingerprint) {
            $params = stream_context_get_params($ctx);
            $cert = $params['options']['ssl']['peer_certificate'];
            openssl_x509_export($cert, $certString);
            $fingerprint = $this->getSha1Fingerprint($certString);
            if ($expectedFingerprint !== $fingerprint) {
                echo "ERROR: Certificate fingerprint for mxr.mozilla.org did NOT match expected value!\n\n";
                echo "Expected: {$expectedFingerprint}\n";
                echo "Received: {$fingerprint}\n";
                exit(1);
            }
        }
        return $response;
    }
}
