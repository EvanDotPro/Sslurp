# Sslurp

v1.0 by Evan Coury

[![Build Status](https://secure.travis-ci.org/EvanDotPro/Sslurp.png?branch=master)](http://travis-ci.org/EvanDotPro/Sslurp)

## Introduction

Dealing with SSL properly in PHP is a pain in the ass. Sslurp aims to make it
suck less. Sslurp can be used as a stand-alone library or a ZF2 module.

**Note:** This library requires PHP with OpenSSL support. This is standard in
most Linux distributions' PHP packages, else you need to ensure you compile
using --with-openssl[=DIR].

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

## Usage


### CLI root CA bundle updater

[update-ca-bundle](https://github.com/EvanDotPro/Sslurp/blob/master/bin/update-ca-bundle)
is a handy command-line tool for fetching and building a PEM certificate bundle
from the latest trusted CAs in the [Mozilla source
tree](https://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt).
It bootstraps the initial trust of the mxr.mozilla.org SSL certificate using
[key pinning](http://tools.ietf.org/html/draft-ietf-websec-key-pinning-02) in
addition to verifying the key with either the system's trusted CA root bundle
or, as a fallback, the included Equifax\_Secure\_CA.pem public key. This
approach minimizes the possibility of MITM attacks at any point during the
process so that you can have a very high certainty that the CA bundle built is
authentic and has not been tampered with.

```
Sslurp Root CA Bundle Updater

Usage:
 ./update-ca-bundle [-o output_file]

Options
 -o	Path/filename to the file to (over)write he update root CA bundle. Default to stdout.
```

### Using Sslurp as a library

In addition to the CLI tool, Sslurp can be used as a library through the OOP
interface. The
[source](https://github.com/EvanDotPro/Sslurp/tree/master/src/Sslurp) _is_ the
API documentation.

```php
<?php
require_once 'autoload_register.php';

$bundle = new \Sslurp\CaRootPemBundle(file_get_contents('ca-bundle.pem'));

if ($bundle->isLatest()) {
    echo 'Your CA root bundle is up to date!' . PHP_EOL;
} else {
    echo 'WARNING! Your CA root bundle is out of date!' . PHP_EOL
       . 'Local CA root bundle is version ' . $bundle->getVersion() . '. '
       . 'Latest version available from Mozilla is ' . $bundle->getMozillaCertData()->getVersion() . '.' . PHP_EOL;

    echo 'Updating...';
    file_put_contents('ca-bundle.pem', $bundle->getUpdatedCaRootBundle());
    echo "\tDone!" . PHP_EOL;
}
```

## License

Sslurp is released under the BSD license. See the included LICENSE file.
