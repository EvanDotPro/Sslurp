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
    protected $version = null;

    /**
     * The date/time of the certdataversion
     *
     * @var DateTime
     */
    protected $dateTime = null;

    /**
     * Get the version number according to CVS.
     *
     * @return string
     */
    public function getVersion()
    {
        if ($this->version === null) {
            if (preg_match('/^.*\$Revision: ([\d\.]+)/m', $this->getContent('Revision:'), $match)) {
                $this->version = $match[1];
            } else {
                throw new \RuntimeException('Unable to detect revision ID.');
            }
        }

        return $this->version;
    }

    /**
     * Get the date/time the certdata was modified by Mozilla according to CVS.
     *
     * @return DateTime
     */
    public function getDateTime()
    {
        if ($this->dateTime === null) {
            if (preg_match('/^.*\$Date: ([\d\/-]+\s+[\d:]+)/m', $this->getContent('Date:'), $match)) {
                $this->dateTime = new DateTime($match[1], new DateTimeZone('UTC'));
            } else {
                throw new \RuntimeException('Unable to detect revision date.');
            }
        }

        return $this->dateTime;
    }

    abstract public function getContent($until = false);
}
