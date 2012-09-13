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

/**
 * This class simply wraps an X.509 resource and exposes some handy stuff via
 * a friendly OOP interface.
 */
class X509Certificate
{
    /**
     * @var X.509 resource
     */
    private $certificate;

    /**
     * @var resource
     */
    private $publicKey;

    /**
     * @var array
     */
    private $publicKeyDetails;

    /**
     * @param $certificate mixed X.509 resource, X.509 certificate string, or path to X.509 certificate file.
     */
    public function __construct($certificate)
    {
        if (is_string($certificate)) {
            if (is_readable($certificate)) {
                $certificate = file_get_contents($certificate);
            }
            // We're surpressing errors here in favor of the more verbose exception below.
            $certificate = @openssl_x509_read($certificate);
        }

        if (@get_resource_type($certificate) !== 'OpenSSL X.509') {
            throw new \InvalidArgumentException('Argument passed to constructor'
                . ' of %s must be an X.509 resource, X.509 certificate string, or'
                . ' valid path to an X.509 certificate.');
        }

        $this->certificate = $certificate;
    }

    /**
     * Get the certificate pin.
     *
     * By Kevin McArthur of StormTide Digital Studios Inc.
     * @KevinSMcArthur / https://github.com/StormTide
     *
     * See http://tools.ietf.org/html/draft-ietf-websec-key-pinning-02
     *
     * @return string
     */
    public function getPin()
    {
        $pubkeydetails = $this->getPublicKeyDetails();
        $pubkeypem     = $pubkeydetails['key'];
        //Convert PEM to DER before SHA1'ing
        $start         = '-----BEGIN PUBLIC KEY-----';
        $end           = '-----END PUBLIC KEY-----';
        $pemtrim       = substr($pubkeypem, (strpos($pubkeypem, $start) + strlen($start)), (strlen($pubkeypem) - strpos($pubkeypem, $end)) * (-1));
        $der           = base64_decode($pemtrim);

        return sha1($der);
    }

    /**
     * Extracts the public key from certificate and prepares it for use by other functions.
     * OOP alias for openssl_pkey_get_public / openssl_get_publickey.
     *
     * @return resource 'OpenSSL key'
     */
    public function getPublicKey()
    {
        if ($this->publicKey === null) {
            $this->publicKey = openssl_get_publickey($this->certificate);
        }

        return $this->publicKey;
    }

    /**
     * This function returns the key details (bits, key, type).
     *
     * @return array
     */
    public function getPublicKeyDetails()
    {
        if ($this->publicKeyDetails === null) {
            $this->publicKeyDetails = openssl_pkey_get_details($this->getPublicKey());
        }

        return $this->publicKeyDetails;
    }
}
