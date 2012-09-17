# Sslurp

v1.0 by Evan Coury

[![Build Status](https://secure.travis-ci.org/EvanDotPro/Sslurp.png?branch=master)](http://travis-ci.org/EvanDotPro/Sslurp)

## Introduction

Dealing with SSL properly in PHP is a pain in the ass and completely insecure by default. Sslurp aims to make it easier to use SSL in PHP safely and securely. Sslurp can be used as a stand-alone library, CLI tool, or a ZF2 module.

**Note:** Sslurp requires PHP with OpenSSL support. This is standard in most Linux distributions' PHP packages, otherwise you need to compile PHP using --with-openssl[=DIR].

## Features / Usage

### Root CA bundle management

Sslurp provides CLI and OOP interfaces for generating a trusted root Certificate Authority (CA) bundle using [certdata.txt](http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1) from the source tree of Mozilla's [Network Security Services (NSS) libraries](https://www.mozilla.org/projects/security/pki/nss/) and keeping it up-to-date. The resulting root CA bundle includes the certificates vetted according to the [Mozilla Root Certificate Program](http://www.mozilla.org/projects/security/certs/policy/) — the same root CA bundle trusted by cURL, Firefox, Chrome, and many other applications, libraries, languages, and operating systems.

Sslurp takes additional steps to protect against MITM attacks while fetching certdata.txt from Mozilla's source tree, ensuring that the generated bundle is truly authentic. When connecting to Mozilla's mxr.mozilla.org domain to fetch the updated certdata.txt, Sslurp forces the use of verified SSL. Sslurp uses the following process to establish the initial trust of the SSL certificate on mxr.mozilla.org:

* Check the SSL\_CERT\_FILE environment variable (used by OpenSSL). If the value is the path to a readable file and valid certificate bundle, Sslurp will use it.
* If the SSL\_CERT\_FILE is not set or points to a non-existent / invalid certificate bundle, Sslurp will search several known/expected locations for the root CA bundle and use the first valid bundle found.
* If a valid bundle is not found in any of the expected paths, Sslurp will finally fall back to using a bundled, pre-verified copy of the root CA's public key which established trust for the mxr.mozilla.org certificate (Equifax Secure Certificate Authority at least until November 2013).

As if that's not enough, Sslurp _additionally_ makes use of [public key pinning](http://tools.ietf.org/html/draft-ietf-websec-key-pinning-02) to further authenticate the authenticity of communications with Mozilla's mxr.mozilla.org domain. If the public key pin for mxr.mozilla.org changes before the expiration date of the current certificate, Sslurp will being to throw an exception, and refuse to update the root CA bundle. If the public key pin changes within the final month or after the expiration date of their current certificate (November, 2013), Sslurp will begin throwing a PHP notice encouraging you to update your copy of Sslurp to get the latest pin.

**You are STRONGLY ENCOURAGED to be using the latest version of Sslurp at all times.**

### CLI root CA bundle updater

[./bin/update-ca-bundle](https://github.com/EvanDotPro/Sslurp/blob/master/bin/update-ca-bundle) is a handy command-line tool for fetching, building, and subsequently updating a root CA bundle in PEM format for use with PHP's OpenSSL support, curl, libcurl, php\_curl, etc. The output generated is fully compatible with the [mk-ca-bundle.pl](https://github.com/bagder/curl/blob/master/lib/mk-ca-bundle.pl) which is used to [generate cURL's trusted bundle](http://curl.haxx.se/docs/caextract.html).

```
Sslurp Root CA Bundle Updater

Usage:
 ./update-ca-bundle [-o output_file]

Options
 -o	Path/filename to the file to (over)write he update root CA bundle. Default to stdout.
```

### Using Sslurp as a library

In addition to the CLI tool, Sslurp can be used as a library through the OOP
interface. The [source](https://github.com/EvanDotPro/Sslurp/tree/master/src/Sslurp) _is_ the API documentation.

```php
<?php
require_once 'vendor/Sslurp/autoload_register.php';

$bundle = new \Sslurp\CaRootPemBundle('ca-bundle.pem');

if ($bundle->isLatest()) {
    echo 'Your CA root bundle is up to date!' . PHP_EOL;
} else {
    echo 'WARNING! Your CA root bundle is out of date!' . PHP_EOL
       . 'Local CA root bundle is version ' . $bundle->getVersion() . '. '
       . 'Latest version available from Mozilla is ' . $bundle->getMozillaCertData()->getVersion() . '.' . PHP_EOL;

    echo 'Updating...';
    $bundle->update();
    echo "\tDone!" . PHP_EOL;
}
```

## Installation

### Composer / Packagist

```
./composer.phar require evandotpro/sslurp
```

### Normal

The `./bin/update-ca-bundle` CLI tool will "just work" out of the box.

Sslurp can _easily_ be used in any existing project, framework, or library.

To use Sslurp as a library in your project, the easiest method is to simply
include the `autoload_register.php` file:

```php
require_once 'vendor/Sslurp/autoload_register.php';
```

Alternatively, if you project supports loading classmap arrays, you may fetch
the classmap without registering an additional SPL autoloader:

```php
$classmap = include 'vendor/Sslurp/autoload_classmap.php';
// Register $classmap with your project's existing classmap autoloader
```

If you have an existing SPL autoloader that allows adding a callable to a stack
instead of directly registering the classmap array, you have the option of
simply getting a closure which can autoload the Sslurp classes:

```php
$sslurpLoader = include 'vendor/Sslurp/autoload_function.php';
// $sslurpLoader is a closure that can be registered with an existing autoloader
```

## To-Do

* **Paranoia level 1000** - Test environment for the ability to call the OpenSSL executable, and if possible, make use of OCSP to _further_ verify the validity of the mxr.mozilla.org domain.

## License

Sslurp is released under the BSD license. See the included LICENSE file.

The generated root CA bundle file is simply a converted version of the original and as such, it is licensed under the same licenses as the Mozilla source: MPL v2.0, GPL v2.0 or LGPL 2.1. See [nss/COPYING](http://mxr.mozilla.org/mozilla/source/security/nss/COPYING?raw=1) for details.
