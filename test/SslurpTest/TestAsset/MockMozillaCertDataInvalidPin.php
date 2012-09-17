<?php

namespace SslurpTest\TestAsset;

use Sslurp\MozillaCertData;

class MockMozillaCertDataInvalidPin extends MozillaCertData
{
    const MOZILLA_MXR_SSL_PIN = 'invalid';
}
