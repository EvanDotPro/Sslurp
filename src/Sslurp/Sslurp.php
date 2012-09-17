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

class Sslurp
{
    /**
     * Sslurp version number
     */
    const VERSION = '1.0-dev';

    /**
     * Locate the system root CA bundle.
     *
     * @return string
     */
    public static function getSystemCaRootBundlePath()
    {
        // If SSL_CERT_FILE env variable points to a valid certificate/bundle, use that.
        // This mimics how OpenSSL uses the SSL_CERT_FILE env variable.
        $envCertFile = getenv('SSL_CERT_FILE');
        if ($envCertFile && is_readable($envCertFile) && openssl_x509_parse(file_get_contents($envCertFile))) {
            // Possibly throw exception instead of ignoring SSL_CERT_FILE if it's invalid?
            return $envCertFile;
        }

        $caBundlePaths = array(
            '/etc/pki/tls/certs/ca-bundle.crt',         // Fedora, RHEL, CentOS (ca-certificates package)
            '/etc/ssl/certs/ca-certificates.crt',       // Debian, Ubuntu, Gentoo, Arch Linux (ca-certificates package)
            '/etc/ssl/ca-bundle.pem',                   // SUSE, openSUSE (ca-certificates package)
            '/usr/local/share/certs/ca-root-nss.crt',   // FreeBSD (ca_root_nss_package)
            '/usr/ssl/certs/ca-bundle.crt',             // Cygwin
            '/opt/local/share/curl/curl-ca-bundle.crt', // OS X macports, curl-ca-bundle package
            '/usr/local/share/curl/curl-ca-bundle.crt', // Default cURL CA bunde path (without --with-ca-bundle option)
            '/usr/share/ssl/certs/ca-bundle.crt',       // Really old RedHat?
        );

        $found = false;
        foreach ($caBundlePaths as $caBundle) {
            if (is_readable($caBundle) && openssl_x509_parse(file_get_contents($caBundle))) {
                $found = true;
                break;
            }
        }

        return $found ? $caBundle : false;
    }
}
