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

use Tymon\JWTAuth\Contracts\Providers\JWT as JWTContract;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Exceptions\TokenRevokedException;
use Tymon\JWTAuth\Support\CustomClaims;
use Tymon\JWTAuth\Support\RefreshFlow;

class Manager
{
    use CustomClaims, RefreshFlow;

    /**
     * The provider.
     *
     * @var \Tymon\JWTAuth\Contracts\Providers\JWT
     */
    protected $provider;

    /**
     * The blacklist.
     *
     * @var \Tymon\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * the payload factory.
     *
     * @var \Tymon\JWTAuth\Factory
     */
    protected $payloadFactory;

    /**
     * The blacklist flag.
     *
     * @var bool
     */
    protected $blacklistEnabled = true;

    /**
     * The logout-all-devices flag.
     *
     * @var bool
     */
    protected $logoutAllDevicesEnabled = false;

    /**
     * the persistent claims.
     *
     * @var array
     */
    protected $persistentClaims = [];

    /**
     * Constructor.
     *
     * @param  \Tymon\JWTAuth\Contracts\Providers\JWT  $provider
     * @param  \Tymon\JWTAuth\Blacklist  $blacklist
     * @param  \Tymon\JWTAuth\Factory  $payloadFactory
     * @return void
     */
    public function __construct(JWTContract $provider, Blacklist $blacklist, Factory $payloadFactory)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return \Tymon\JWTAuth\Token
     */
    public function encode(Payload $payload)
    {
        $token = $this->provider->encode($payload->get());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     * @param  bool  $checkBlacklist
     * @return \Tymon\JWTAuth\Payload
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenBlacklistedException
     */
    public function decode(Token $token, $checkBlacklist = true)
    {
        $payloadArray = $this->provider->decode($token->get());

        $payload = $this->payloadFactory
                        ->setRefreshFlow($this->refreshFlow)
                        ->customClaims($payloadArray)
                        ->make();

        if ($checkBlacklist && $this->blacklistEnabled && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        if ($checkBlacklist && $this->logoutAllDevicesEnabled && $this->blacklist->hasSubject($payload)) {
            throw new TokenRevokedException('The token has been revoked');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     * @param  bool  $forceForever
     * @param  bool  $resetClaims
     * @return \Tymon\JWTAuth\Token
     */
    public function refresh(Token $token, $forceForever = false, $resetClaims = false)
    {
        $this->setRefreshFlow();

        $claims = $this->buildRefreshClaims($this->decode($token));

        if ($this->blacklistEnabled) {
            // Invalidate old token
            $this->invalidate($token, $forceForever);
        }

        // Return the new token
        return $this->encode(
            $this->payloadFactory->customClaims($claims)->make($resetClaims)
        );
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     * @param  bool  $forceForever
     * @return bool
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function invalidate(Token $token, $forceForever = false)
    {
        if (! $this->blacklistEnabled) {
            throw new JWTException('You must have the blacklist enabled to invalidate a token.');
        }

        return call_user_func(
            [$this->blacklist, $forceForever ? 'addForever' : 'add'],
            $this->decode($token, false)
        );
    }

    /**
     * Invalidate all tokens for a payload subject.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function invalidateAll(Payload $payload)
    {
        if (! $this->logoutAllDevicesEnabled) {
            throw new JWTException('You must have logout all devices enabled to invalidate all tokens.');
        }

        return $this->blacklist->addSubject($payload);
    }

    /**
     * Build the claims to go into the refreshed token.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return array
     */
    protected function buildRefreshClaims(Payload $payload)
    {
        $claims = $payload->toArray();

        // Get the claims to be persisted from the payload
        $persistentClaims = collect($claims)
            ->only($this->persistentClaims)
            ->toArray();

        $persistentClaims = array_merge(
            $persistentClaims,
            array_key_exists('prv', $claims) ? ['prv' => $claims['prv']] : []
        );

        // persist the relevant claims
        return array_merge(
            $this->customClaims,
            $persistentClaims,
            [
                'sub' => $payload['sub'],
                'iat' => $payload['iat'],
            ]
        );
    }

    /**
     * Get the Payload Factory instance.
     *
     * @return \Tymon\JWTAuth\Factory
     */
    public function getPayloadFactory()
    {
        return $this->payloadFactory;
    }

    /**
     * Get the JWTProvider instance.
     *
     * @return \Tymon\JWTAuth\Contracts\Providers\JWT
     */
    public function getJWTProvider()
    {
        return $this->provider;
    }

    /**
     * Get the Blacklist instance.
     *
     * @return \Tymon\JWTAuth\Blacklist
     */
    public function getBlacklist()
    {
        return $this->blacklist;
    }

    /**
     * Set whether the blacklist is enabled.
     *
     * @param  bool  $enabled
     * @return $this
     */
    public function setBlacklistEnabled($enabled)
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }

    /**
     * Set whether logout-all-devices is enabled.
     *
     * @param  bool  $enabled
     * @return $this
     */
    public function setLogoutAllDevicesEnabled($enabled)
    {
        $this->logoutAllDevicesEnabled = (bool) $enabled;

        return $this;
    }

    /**
     * Get whether logout-all-devices is enabled.
     *
     * @return bool
     */
    public function getLogoutAllDevicesEnabled()
    {
        return $this->logoutAllDevicesEnabled;
    }

    /**
     * Set the claims to be persisted when refreshing a token.
     *
     * @param  array  $claims
     * @return $this
     */
    public function setPersistentClaims(array $claims)
    {
        $this->persistentClaims = $claims;

        return $this;
    }
}
