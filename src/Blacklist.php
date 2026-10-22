<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Contracts\Providers\Storage;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Support\Utils;

class Blacklist
{
    /**
     * The storage.
     *
     * @var \Tymon\JWTAuth\Contracts\Providers\Storage
     */
    protected $storage;

    /**
     * The grace period when a token is blacklisted. In seconds.
     *
     * @var int
     */
    protected $gracePeriod = 0;

    /**
     * Number of minutes from issue date in which a JWT can be refreshed.
     *
     * @var int|null
     */
    protected $refreshTTL = 20160;

    /**
     * Number of minutes the token is valid for.
     *
     * @var int|null
     */
    protected $ttl = 60;

    /**
     * The token leeway in seconds.
     *
     * @var int
     */
    protected $leeway = 0;

    /**
     * Number of minutes until a subject revocation record expires.
     *
     * @var int|null
     */
    protected $logoutAllDevicesTTL;

    /**
     * The unique key held within the blacklist.
     *
     * @var string
     */
    protected $key = 'jti';

    /**
     * Constructor.
     *
     * @param  \Tymon\JWTAuth\Contracts\Providers\Storage  $storage
     * @return void
     */
    public function __construct(Storage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function add(Payload $payload)
    {
        // if there is no exp claim then add the jwt to
        // the blacklist indefinitely
        if (! $payload->hasKey('exp')) {
            return $this->addForever($payload);
        }

        // if we have already added this token to the blacklist
        if (! empty($this->storage->get($this->getKey($payload)))) {
            return true;
        }

        $this->storage->add(
            $this->getKey($payload),
            ['valid_until' => $this->getGraceTimestamp()],
            $this->getMinutesUntilExpired($payload)
        );

        return true;
    }

    /**
     * Get the number of minutes until the token expiry.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return int
     */
    protected function getMinutesUntilExpired(Payload $payload)
    {
        $exp = Utils::timestamp($payload['exp']);
        $iat = Utils::timestamp($payload['iat']);

        // get the latter of the two expiration dates and find
        // the number of minutes until the expiration date,
        // plus 1 minute to avoid overlap
        $expiration = $exp->max($iat->addMinutes($this->refreshTTL ?? 0))->addMinute();

        $minutes = method_exists($expiration, 'diffInRealMinutes')
            ? $expiration->diffInRealMinutes()
            : $expiration->diffInUTCMinutes();

        return (int) ceil(abs($minutes));
    }

    /**
     * Add the token (jti claim) to the blacklist indefinitely.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function addForever(Payload $payload)
    {
        $this->storage->forever($this->getKey($payload), 'forever');

        return true;
    }

    /**
     * Add a subject revocation cutoff to the blacklist storage.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function addSubject(Payload $payload)
    {
        $key = $this->getSubjectKey($payload);
        $cutoff = (int) Utils::now()->getTimestamp();
        $cutoffRecord = ['cutoff' => $cutoff];
        $ttl = $this->getLogoutAllDevicesTTL();

        $this->storage->destroy($key);

        if (is_null($ttl)) {
            $this->storage->forever($key, $cutoffRecord);

            return true;
        }

        $this->storage->add($key, $cutoffRecord, $ttl);

        return true;
    }

    /**
     * Determine whether the payload's subject has been revoked.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function hasSubject(Payload $payload)
    {
        if (! $payload->hasKey('sub')) {
            return false;
        }

        $record = $this->storage->get($this->getSubjectKey($payload));

        if (empty($record) || ! is_array($record) || ! array_key_exists('cutoff', $record)) {
            return false;
        }

        if (! $payload->hasKey('iat')) {
            return true;
        }

        return (int) $payload['iat'] <= (int) $record['cutoff'];
    }

    /**
     * Determine whether the token has been blacklisted.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function has(Payload $payload)
    {
        $val = $this->storage->get($this->getKey($payload));

        // exit early if the token was blacklisted forever,
        if ($val === 'forever') {
            return true;
        }

        // check whether the expiry + grace has past
        return ! empty($val) && ! Utils::isFuture($val['valid_until']);
    }

    /**
     * Remove the token (jti claim) from the blacklist.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function remove(Payload $payload)
    {
        return $this->storage->destroy($this->getKey($payload));
    }

    /**
     * Remove all tokens from the blacklist.
     *
     * @return bool
     */
    public function clear()
    {
        $this->storage->flush();

        return true;
    }

    /**
     * Get the timestamp when the blacklist comes into effect
     * This defaults to immediate (0 seconds).
     *
     * @return int
     */
    protected function getGraceTimestamp()
    {
        return Utils::now()->addSeconds($this->gracePeriod)->getTimestamp();
    }

    /**
     * Set the grace period.
     *
     * @param  int  $gracePeriod
     * @return $this
     */
    public function setGracePeriod($gracePeriod)
    {
        $this->gracePeriod = (int) $gracePeriod;

        return $this;
    }

    /**
     * Get the grace period.
     *
     * @return int
     */
    public function getGracePeriod()
    {
        return $this->gracePeriod;
    }

    /**
     * Get the unique key held within the blacklist.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return mixed
     */
    public function getKey(Payload $payload)
    {
        return $payload($this->key);
    }

    /**
     * Get the unique subject revocation key.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return string
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function getSubjectKey(Payload $payload)
    {
        if (! $payload->hasKey('sub')) {
            throw new JWTException('The token does not contain the required subject claim.');
        }

        $identity = [
            'sub' => (string) $payload['sub'],
            'prv' => $payload->hasKey('prv') ? (string) $payload['prv'] : null,
        ];

        return 'logout_all_devices:'.sha1(json_encode($identity));
    }

    /**
     * Set the unique key held within the blacklist.
     *
     * @param  string  $key
     * @return $this
     */
    public function setKey($key)
    {
        $this->key = value($key);

        return $this;
    }

    /**
     * Set the refresh time limit.
     *
     * @param  int|null  $ttl
     * @return $this
     */
    public function setRefreshTTL($ttl)
    {
        $this->refreshTTL = $ttl !== null ? (int) $ttl : null;

        return $this;
    }

    /**
     * Set the token ttl.
     *
     * @param  int|null  $ttl
     * @return $this
     */
    public function setTTL($ttl)
    {
        $this->ttl = $ttl !== null ? (int) $ttl : null;

        return $this;
    }

    /**
     * Set the token leeway in seconds.
     *
     * @param  int|null  $leeway
     * @return $this
     */
    public function setLeeway($leeway)
    {
        $this->leeway = $leeway !== null ? (int) $leeway : 0;

        return $this;
    }

    /**
     * Get the refresh time limit.
     *
     * @return int|null
     */
    public function getRefreshTTL()
    {
        return $this->refreshTTL;
    }

    /**
     * Set the logout-all-devices time limit.
     *
     * @param  int|null  $ttl
     * @return $this
     */
    public function setLogoutAllDevicesTTL($ttl)
    {
        $this->logoutAllDevicesTTL = is_null($ttl) ? null : (int) $ttl;

        return $this;
    }

    /**
     * Get the effective logout-all-devices time limit.
     *
     * @return int|null
     */
    public function getLogoutAllDevicesTTL()
    {
        if (is_null($this->ttl) || is_null($this->refreshTTL)) {
            return null;
        }

        $leewayInMinutes = (int) ceil(max($this->leeway, 0) / 60);
        $minimum = max((int) $this->ttl, (int) $this->refreshTTL) + 1 + $leewayInMinutes;

        if (is_null($this->logoutAllDevicesTTL)) {
            return $minimum;
        }

        return max((int) $this->logoutAllDevicesTTL, $minimum);
    }
}
