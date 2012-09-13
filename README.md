# Sslurp

v0.1 by Evan Coury

[![Build Status](https://secure.travis-ci.org/EvanDotPro/Sslurp.png?branch=master)](http://travis-ci.org/EvanDotPro/Sslurp)

## Introduction

**WARNING:** This library is currently undergoing review and should not yet be
considered stable or secure. Proceed with caution...

Dealing with SSL properly in PHP is a pain in the ass. Sslurp
aims to make it suck less. Sslurp can be used as a stand-alone library or a ZF2
module.

**Note:** This library requires PHP with OpenSSL support. This is standard in
most Linux distributions' PHP packages, else you need to ensure you compile
using --with-openssl[=DIR].

### CLI Root CA Bundle Updater

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

## License

Sslurp is released under the BSD license. See the included LICENSE file.
