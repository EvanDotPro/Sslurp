# Sslurp

v0.1 by Evan Coury

[![Build Status](https://secure.travis-ci.org/EvanDotPro/Sslurp.png?branch=master)](http://travis-ci.org/EvanDotPro/Sslurp)

## Introduction

**WARNING:** This library is currently undergoing review and should not yet be
considered stable or secure. Proceed with caution...

Dealing with SSL properly in PHP is a pain in the ass. Sslurp
aims to make it suck less. Sslurp can be used as a stand-alone library or a ZF2
module.


### CLI Root CA Bundle Updater

[update-ca-bundle.php](https://github.com/EvanDotPro/Sslurp/blob/master/bin/update-ca-bundle.php)
is a handy command-line tool for fetching and building a PEM certificate bundle
from the latest trusted CAs in the [Mozilla source
tree](https://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt).
As a parameter, it requires that you pass it the proper SHA1 fingerprint of the
SSL certificate on mxr.mozilla.org. You can easily find the latest fingerprint
by going to [https://evan.pro/ssl/](https://evan.pro/ssl/).

```
Sslurp Root CA Bundle Updater

Usage:
 ./update-ca-bundle.php [-o output_file]

Options
 -o	Path/filename to the file to (over)write he update root CA bundle. Default to stdout.
```

## License

Sslurp is released under the BSD license. See the included LICENSE file.
