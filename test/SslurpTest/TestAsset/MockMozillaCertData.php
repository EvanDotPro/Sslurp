<?php

namespace SslurpTest\TestAsset;

use Sslurp\MozillaCertData;

class MockMozillaCertData extends MozillaCertData
{
    public function getContent()
    {
        return 'foo';
    }
}
