#!/usr/bin/env php
<?php

require_once __DIR__ . '/../autoload_register.php';

$help = <<<help
Sslurp Root CA Bundle Updater

Usage:
 {$argv[0]} [-o output_file] [sha1_fingerprint]

Arguments
 sha1_fingerprint\tThe expected SHA1 fingerprint of the SSL certificate on mxr.mozilla.org.

Options
 -o\tPath/filename to the file to (over)write he update root CA bundle. Default to stdout.

To get the expected SHA1 fingerprint, go to https://evan.pro/ssl/ in your web browser.
Be sure that your browser shows a proper SSL connection with no warnings.

Sslurp home page: https://github.com/EvanDotPro/Sslurp
help;

$outputFile = false;
for ($i=1; $i<$argc; $i++) {
    switch ($argv[$i]) {
        case '-o':
            $outputFile = $argv[++$i];
            break;
        default:
            $fingerprint = $argv[$i];
            break;
    }
}

if (!isset($fingerprint)) {
    echo $help;
    exit;
}

$caBundleBuilder = new Sslurp\RootCaBundleBuilder();
$caBundle        = $caBundleBuilder->updateRootCaBundle($fingerprint, $outputFile);
if (!$outputFile) {
    echo $caBundle;
} else {
    echo "Updated root CA bundle written to {$outputFile}.\n";
}
