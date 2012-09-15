<?php
/**
 * This file is part of Sslurp.
 * https://github.com/EvanDotPro/Sslurp
 *
 * (c) Evan Coury <me@evancoury.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Sslurp;

use DateTime;
use DateTimeZone;

abstract class AbstractCaRootData
{
    /**
     * The CVS version ID
     *
     * @var string
     */
    private $version = null;

    /**
     * The date/time of the version commit
     *
     * @var DateTime
     */
    private $dateTime = null;

    /**
     * Get the version number
     *
     * @return string
     */
    public function getVersion()
    {
        if ($this->version === null) {
            if (preg_match('/^#?\s?(CVS_ID\s+\".*\")/m', $this->getContent(), $match)) {
                $parts = explode(' ', $match[1]);
                $this->version = $parts[6];
                $this->dateTime = new DateTime($parts[9] . ' ' . $parts[10], new DateTimeZone('UTC'));
            } else {
                throw new \RuntimeException('Unable to detect CVS version ID.');
            }
        }

        return $this->version;
    }

    /**
     * Get the date/time of the last update
     *
     * @return DateTime
     */
    public function getDateTime()
    {
        if ($this->dateTime === null) {
            $this->getVersion();
        }

        return $this->dateTime;
    }

    abstract protected function getContent();
}
