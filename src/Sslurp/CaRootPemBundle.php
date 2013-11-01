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

use SplFileObject;

class CaRootPemBundle extends AbstractCaRootData
{
    /**
     * @var SplFileObject
     */
    protected $fileObject = null;

    /**
     * @var string
     */
    protected $pemContent = null;

    /**
     * @var MozillaCertData
     */
    protected $mozCertData = null;

    public function __construct($filename, MozillaCertData $mozCertData = null)
    {
        if (!file_exists($filename)) {
            touch($filename);
        }
        $this->fileObject  = new SplFileObject($filename, 'r+');
        $this->mozCertData = $mozCertData ?: new MozillaCertData();
    }

    /**
     * Return the content of the PEM bundle
     */
    public function getContent($until = false)
    {
        if ($this->pemContent === null) {
            $this->pemContent = '';
            while (!$this->fileObject->eof()) $this->pemContent .= $this->fileObject->fgets();
            //$this->pemContent = $this->fileObject->getUpdatedCaRootBundle();
        }

        if ($until) {
            return substr($this->pemContent, 0, strpos($this->pemContent, "\n", strpos($this->pemContent, $until)));
        }

        return $this->pemContent;
    }

    public function getMozillaCertData()
    {
        return $this->mozCertData;
    }

    public function isLatest()
    {
        return $this->getVersion() === $this->mozCertData->getVersion();
    }

    public function getUpdatedCaRootBundle()
    {
        return $this->buildBundle($this->mozCertData->getContent());
    }

    protected function buildBundle($rawCertData)
    {
        $rawCertData = explode("\n", $rawCertData);
        $caBundle = <<<EOT
##
## Bundle of CA Root Certificates
##
## Generated with Sslurp (https://github.com/EvanDotPro/Sslurp)
##
## This is a bundle of X.509 certificates of public Certificate Authorities.
## These were automatically extracted from Mozilla's root certificates
## file (certdata.txt). This file can be found in the Mozilla source tree:
## /mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt
##
## http://www.mozilla.org/projects/security/certs/policy/
## http://www.mozilla.org/projects/security/pki/nss/
##
## This file contains the certificates in PEM format and therefore
## can be directly used with curl / libcurl / php_curl, or with
## an Apache+mod_ssl webserver for SSL client authentication.
## Just configure this file as the SSLCACertificateFile.
##

EOT;
        $caName = '';
        while (($line = array_shift($rawCertData)) !== null) {
            if (preg_match('/^#|^\s*$/', $line)) {
                continue;
            }

            $line = rtrim($line);

            if (preg_match('/^CVS_ID\s+\"(.*)\"/', $line, $match)) {
                $caBundle .= "# {$match[1]}\n";
            }

            if (preg_match('/^CKA_LABEL\s+[A-Z0-9]+\s+\"(.*)\"/', $line, $match)) {
                $caName = $match[1];
            }

            if (preg_match('/^CKA_VALUE MULTILINE_OCTAL/', $line)) {
                $data = '';
                while ($line = array_shift($rawCertData)) {
                    if (preg_match('/^END/', $line)) {
                        break;
                    }

                    $line = rtrim($line);
                    $octets = explode('\\', $line);
                    array_shift($octets);

                    foreach ($octets as $oct) {
                        $data .= chr(octdec($oct));
                    }
                }

                $caBundle .= $this->buildPemString($caName, $data);
            }
        }

        return $caBundle;
    }

    protected function buildPemString($caName, $data)
    {
        return "\n{$caName}\n"
             . str_repeat('=', strlen($caName)) . "\n"
             . "-----BEGIN CERTIFICATE-----\n"
             . chunk_split(base64_encode($data), 76, "\n")
             . "-----END CERTIFICATE-----\n";
    }
}
