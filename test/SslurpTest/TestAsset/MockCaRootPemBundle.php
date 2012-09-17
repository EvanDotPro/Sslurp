<?php

namespace SslurpTest\TestAsset;

use Sslurp\CaRootPemBundle;

class MockCaRootPemBundle extends CaRootPemBundle
{
    //protected $dateTime = 'for testing';
    public function setPemContent($pemContent)
    {
        $this->pemContent = $pemContent;
    }
}
