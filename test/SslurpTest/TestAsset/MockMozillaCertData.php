<?php

namespace SslurpTest\TestAsset;

use Sslurp\MozillaCertData;

class MockMozillaCertData extends MozillaCertData
{
    public static $allowOnlineTest = false;

    public function setCertData($certData)
    {
        $this->certData = $certData;
    }

    protected function fetchLatestCertData($until = false)
    {
        if (static::$allowOnlineTest) {
            return parent::fetchLatestCertData($until);
        }
        $return = $this->certData ?: file_get_contents(__DIR__ . '/../_files/certdata.txt');
        if ($until) {
            return substr($return, 0, strpos($return, "\n", strpos($return, $until)));
        }

        return $return;
    }
}
