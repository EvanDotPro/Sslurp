<?php

namespace SslurpTest\TestAsset;

define('PAST', time() - 100);

class MockMozillaCertDataInvalidPinAndExp extends MockMozillaCertDataInvalidPin
{
    const MOZILLA_MXR_SSL_EXP = PAST;
}
