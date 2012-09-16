<?php

namespace SslurpTest\TestAsset;

use Sslurp\MozillaCertData;

class MockMozillaCertDataFetchLatest extends MozillaCertData
{
    protected function fetchLatestCertData($until = false)
    {
        return 'latest';
    }
}
