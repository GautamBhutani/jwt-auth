<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test;

use Mockery;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Contracts\Providers\JWT;
use Tymon\JWTAuth\Contracts\Providers\Storage;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Exceptions\TokenRevokedException;
use Tymon\JWTAuth\Factory;
use Tymon\JWTAuth\Manager;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Validators\PayloadValidator;

class ManagerTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Contracts\Providers\JWT
     */
    protected $jwt;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Factory
     */
    protected $factory;

    /**
     * @var \Tymon\JWTAuth\Manager
     */
    protected $manager;

    /**
     * @var \Mockery\MockInterface
     */
    protected $validator;

    public function setUp(): void
    {
        parent::setUp();

        $this->jwt = Mockery::mock(JWT::class);
        $this->blacklist = Mockery::mock(Blacklist::class);
        $this->factory = Mockery::mock(Factory::class);
        $this->manager = new Manager($this->jwt, $this->blacklist, $this->factory);
        $this->validator = Mockery::mock(PayloadValidator::class);
    }

    /** @test */
    public function it_should_encode_a_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);

        $this->jwt->shouldReceive('encode')->with($payload->toArray())->andReturn('foo.bar.baz');

        $token = $this->manager->encode($payload);

        $this->assertEquals($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_decode_a_token()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);

        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $payload = $this->manager->decode($token);

        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertSame($payload->count(), 6);
    }

    /** @test */
    public function it_should_throw_exception_when_token_is_blacklisted()
    {
        $this->expectException(TokenBlacklistedException::class);
        $this->expectExceptionMessage('The token has been blacklisted');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->with($payload->toArray())->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(true);

        $this->manager->decode($token);
    }

    /** @test */
    public function it_should_not_check_subject_revocation_when_logout_all_devices_is_disabled()
    {
        $claims = [
            'sub' => 1,
            'iat' => $this->testNowTimestamp,
            'jti' => 'foo',
        ];

        $token = new Token('foo.bar.baz');
        $payload = Mockery::mock(Payload::class);

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($claims);

        $this->factory->shouldReceive('setRefreshFlow')->once()->with(false)->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->once()->with($claims)->andReturn($this->factory);
        $this->factory->shouldReceive('make')->once()->andReturn($payload);

        $this->blacklist->shouldReceive('has')->never();
        $this->blacklist->shouldReceive('hasSubject')->never();

        $this->manager->setBlacklistEnabled(false)->setLogoutAllDevicesEnabled(false);

        $this->assertSame($payload, $this->manager->decode($token));
    }

    /** @test */
    public function it_should_throw_exception_when_token_subject_is_blacklisted()
    {
        $this->expectException(TokenRevokedException::class);
        $this->expectExceptionMessage('The token has been revoked');

        $claims = [
            'sub' => 1,
            'iat' => $this->testNowTimestamp,
            'jti' => 'foo',
        ];

        $token = new Token('foo.bar.baz');
        $payload = Mockery::mock(Payload::class);

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($claims);

        $this->factory->shouldReceive('setRefreshFlow')->once()->with(false)->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->once()->with($claims)->andReturn($this->factory);
        $this->factory->shouldReceive('make')->once()->andReturn($payload);

        $this->blacklist->shouldReceive('has')->never();
        $this->blacklist->shouldReceive('hasSubject')->once()->with($payload)->andReturn(true);

        $this->manager->setBlacklistEnabled(false)->setLogoutAllDevicesEnabled(true);

        $this->manager->decode($token);
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->twice()->with('foo.bar.baz')->andReturn($payload->toArray());
        $this->jwt->shouldReceive('encode')->with($payload->toArray())->andReturn('baz.bar.foo');

        $this->factory->shouldReceive('setRefreshFlow')->with(true)->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);
        $this->blacklist->shouldReceive('add')->once()->with($payload);

        $token = $this->manager->refresh($token);

        // $this->assertArrayHasKey('ref', $payload);
        $this->assertInstanceOf(Token::class, $token);
        $this->assertEquals('baz.bar.foo', $token);
    }

    /** @test */
    public function it_should_refresh_a_token_and_preserve_prv()
    {
        $decodedClaims = ['sub' => '42', 'iat' => 123, 'prv' => 'provider-hash', 'jti' => 'foo'];
        $token = new Token('foo.bar.baz');

        $decodedPayload = Mockery::mock(Payload::class);
        $decodedPayload->shouldReceive('toArray')->once()->andReturn($decodedClaims);
        $decodedPayload->shouldReceive('offsetGet')->with('sub')->andReturn('42');
        $decodedPayload->shouldReceive('offsetGet')->with('iat')->andReturn(123);

        $replacementPayload = Mockery::mock(Payload::class);
        $replacementPayload->shouldReceive('get')->once()->andReturn(['sub' => '42', 'iat' => 123, 'prv' => 'provider-hash']);

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($decodedClaims);
        $this->jwt->shouldReceive('encode')
            ->once()
            ->with(['sub' => '42', 'iat' => 123, 'prv' => 'provider-hash'])
            ->andReturn('baz.bar.foo');

        $this->factory->shouldReceive('setRefreshFlow')->once()->with(true)->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->once()->with($decodedClaims)->andReturn($this->factory);
        $this->factory->shouldReceive('make')->once()->andReturn($decodedPayload);
        $this->factory->shouldReceive('customClaims')
            ->once()
            ->with(['sub' => '42', 'iat' => 123, 'prv' => 'provider-hash'])
            ->andReturn($this->factory);
        $this->factory->shouldReceive('make')->once()->with(false)->andReturn($replacementPayload);

        $this->blacklist->shouldReceive('hasSubject')->never();
        $this->blacklist->shouldReceive('has')->never();

        $this->manager->setBlacklistEnabled(false)->setPersistentClaims([]);

        $this->assertSame('baz.bar.foo', (string) $this->manager->refresh($token));
    }

    /** @test */
    public function it_should_not_refresh_when_token_subject_is_blacklisted()
    {
        $this->expectException(TokenRevokedException::class);

        $claims = [
            'sub' => 1,
            'iat' => $this->testNowTimestamp,
            'jti' => 'foo',
        ];

        $token = new Token('foo.bar.baz');
        $payload = Mockery::mock(Payload::class);

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($claims);
        $this->jwt->shouldReceive('encode')->never();

        $this->factory->shouldReceive('setRefreshFlow')->once()->with(true)->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->once()->with($claims)->andReturn($this->factory);
        $this->factory->shouldReceive('make')->once()->andReturn($payload);

        $this->blacklist->shouldReceive('has')->never();
        $this->blacklist->shouldReceive('hasSubject')->once()->with($payload)->andReturn(true);

        $this->manager->setBlacklistEnabled(false)->setLogoutAllDevicesEnabled(true);

        $this->manager->refresh($token);
    }

    /** @test */
    public function it_should_still_throw_token_blacklisted_exception_for_single_token_blacklist_entries()
    {
        $this->expectException(TokenBlacklistedException::class);
        $this->expectExceptionMessage('The token has been blacklisted');

        $claims = [
            'sub' => 1,
            'iat' => $this->testNowTimestamp,
            'jti' => 'foo',
        ];

        $token = new Token('foo.bar.baz');
        $payload = Mockery::mock(Payload::class);

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($claims);

        $this->factory->shouldReceive('setRefreshFlow')->once()->with(false)->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->once()->with($claims)->andReturn($this->factory);
        $this->factory->shouldReceive('make')->once()->andReturn($payload);

        $this->blacklist->shouldReceive('has')->once()->with($payload)->andReturn(true);
        $this->blacklist->shouldReceive('hasSubject')->never();

        $this->manager->setBlacklistEnabled(true)->setLogoutAllDevicesEnabled(true);

        $this->manager->decode($token);
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->with($payload->toArray())->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $this->blacklist->shouldReceive('add')->with($payload)->andReturn(true);

        $this->manager->invalidate($token);
    }

    /** @test */
    public function it_should_force_invalidate_a_token_forever()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->with($payload->toArray())->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $this->blacklist->shouldReceive('addForever')->with($payload)->andReturn(true);

        $this->manager->invalidate($token, true);
    }

    /** @test */
    public function it_should_throw_an_exception_when_enable_blacklist_is_set_to_false()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('You must have the blacklist enabled to invalidate a token.');

        $token = new Token('foo.bar.baz');

        $this->manager->setBlacklistEnabled(false)->invalidate($token);
    }

    /** @test */
    public function it_should_throw_an_exception_when_invalidate_all_is_disabled()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('You must have logout all devices enabled to invalidate all tokens.');

        $payload = Mockery::mock(Payload::class);

        $this->blacklist->shouldReceive('addSubject')->never();

        $this->manager->setLogoutAllDevicesEnabled(false)->invalidateAll($payload);
    }

    /** @test */
    public function it_should_invalidate_all_tokens_for_a_subject()
    {
        $payload = Mockery::mock(Payload::class);

        $this->blacklist->shouldReceive('addSubject')->once()->with($payload)->andReturn(true);

        $this->manager->setLogoutAllDevicesEnabled(true);

        $this->assertTrue($this->manager->invalidateAll($payload));
    }

    /** @test */
    public function it_should_return_true_when_invalidating_all_tokens_with_a_void_return_storage_add_method()
    {
        $storage = new class implements Storage
        {
            public $destroyed = [];
            public $records = [];

            public function add($key, $value, $minutes)
            {
                $this->records[$key] = ['value' => $value, 'minutes' => $minutes];
            }

            public function forever($key, $value)
            {
                $this->records[$key] = ['value' => $value, 'minutes' => null];
            }

            public function get($key)
            {
                return $this->records[$key]['value'] ?? null;
            }

            public function destroy($key)
            {
                $this->destroyed[] = $key;
                unset($this->records[$key]);

                return true;
            }

            public function flush()
            {
                $this->records = [];
            }
        };

        $blacklist = (new Blacklist($storage))->setTTL(60)->setRefreshTTL(120);
        $manager = (new Manager($this->jwt, $blacklist, $this->factory))->setLogoutAllDevicesEnabled(true);

        $claims = [
            'sub' => '42',
            'prv' => 'provider-hash',
        ];

        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('hasKey')->andReturnUsing(function ($key) use ($claims) {
            return array_key_exists($key, $claims);
        });
        $payload->shouldReceive('offsetGet')->andReturnUsing(function ($key) use ($claims) {
            return $claims[$key] ?? null;
        });

        $this->assertTrue($manager->invalidateAll($payload));

        $subjectKey = 'logout_all_devices:'.sha1(json_encode($claims));

        $this->assertSame([$subjectKey], $storage->destroyed);
        $this->assertArrayHasKey($subjectKey, $storage->records);
        $this->assertSame(['cutoff' => $this->testNowTimestamp], $storage->records[$subjectKey]['value']);
        $this->assertSame(121, $storage->records[$subjectKey]['minutes']);
    }

    /** @test */
    public function it_should_set_and_get_whether_logout_all_devices_is_enabled()
    {
        $this->assertFalse($this->manager->getLogoutAllDevicesEnabled());

        $this->manager->setLogoutAllDevicesEnabled(true);

        $this->assertTrue($this->manager->getLogoutAllDevicesEnabled());
    }

    /** @test */
    public function it_should_get_the_payload_factory()
    {
        $this->assertInstanceOf(Factory::class, $this->manager->getPayloadFactory());
    }

    /** @test */
    public function it_should_get_the_jwt_provider()
    {
        $this->assertInstanceOf(JWT::class, $this->manager->getJWTProvider());
    }

    /** @test */
    public function it_should_get_the_blacklist()
    {
        $this->assertInstanceOf(Blacklist::class, $this->manager->getBlacklist());
    }
}
