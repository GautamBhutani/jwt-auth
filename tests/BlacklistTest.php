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
use Tymon\JWTAuth\Contracts\Providers\Storage;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Validators\PayloadValidator;

class BlacklistTest extends AbstractTestCase
{
    /**
     * @var \Tymon\JWTAuth\Contracts\Providers\Storage|\Mockery\MockInterface
     */
    protected $storage;

    /**
     * @var \Tymon\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Validators\Validator
     */
    protected $validator;

    public function setUp(): void
    {
        parent::setUp();

        $this->storage = Mockery::mock(Storage::class);
        $this->blacklist = new Blacklist($this->storage);
        $this->validator = Mockery::mock(PayloadValidator::class);
    }

    /** @test */
    public function it_should_add_a_valid_token_to_the_blacklist()
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

        $refreshTTL = 20161;

        $this->storage->shouldReceive('get')
            ->with('foo')
            ->once()
            ->andReturn([]);

        $this->storage->shouldReceive('add')
            ->with('foo', ['valid_until' => $this->testNowTimestamp], $refreshTTL + 1)
            ->once();

        $this->blacklist->setRefreshTTL($refreshTTL)->add($payload);
    }

    /** @test */
    public function it_should_add_a_token_with_no_exp_to_the_blacklist_forever()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);

        $this->storage->shouldReceive('forever')->with('foo', 'forever')->once();
        $this->blacklist->add($payload);
    }

    /** @test */
    public function it_should_return_true_when_adding_an_expired_token_to_the_blacklist()
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

        $payload = new Payload($collection, $this->validator, true);

        $refreshTTL = 20161;

        $this->storage->shouldReceive('get')
            ->with('foo')
            ->once()
            ->andReturn([]);

        $this->storage->shouldReceive('add')
            ->with('foo', ['valid_until' => $this->testNowTimestamp], $refreshTTL + 1)
            ->once();

        $this->assertTrue($this->blacklist->setRefreshTTL($refreshTTL)->add($payload));
    }

    /** @test */
    public function it_should_return_true_early_when_adding_an_item_and_it_already_exists()
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

        $payload = new Payload($collection, $this->validator, true);

        $refreshTTL = 20161;

        $this->storage->shouldReceive('get')
            ->with('foo')
            ->once()
            ->andReturn(['valid_until' => $this->testNowTimestamp]);

        $this->storage->shouldReceive('add')
            ->with('foo', ['valid_until' => $this->testNowTimestamp], $refreshTTL + 1)
            ->never();

        $this->assertTrue($this->blacklist->setRefreshTTL($refreshTTL)->add($payload));
    }

    /** @test */
    public function it_should_check_whether_a_token_has_been_blacklisted()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];

        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);

        $this->storage->shouldReceive('get')->with('foobar')->once()->andReturn(['valid_until' => $this->testNowTimestamp]);

        $this->assertTrue($this->blacklist->has($payload));
    }

    public function blacklist_provider()
    {
        return [
            [null],
            [0],
            [''],
            [[]],
            [['valid_until' => strtotime('+1day')]],
        ];
    }

    /**
     * @test
     *
     * @dataProvider blacklist_provider
     *
     * @param  mixed  $result
     */
    public function it_should_check_whether_a_token_has_not_been_blacklisted($result)
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];

        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);

        $this->storage->shouldReceive('get')->with('foobar')->once()->andReturn($result);
        $this->assertFalse($this->blacklist->has($payload));
    }

    /** @test */
    public function it_should_check_whether_a_token_has_been_blacklisted_forever()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);

        $this->storage->shouldReceive('get')->with('foobar')->once()->andReturn('forever');

        $this->assertTrue($this->blacklist->has($payload));
    }

    /** @test */
    public function it_should_check_whether_a_token_has_been_blacklisted_when_the_token_is_not_blacklisted()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);

        $this->storage->shouldReceive('get')->with('foobar')->once()->andReturn(null);

        $this->assertFalse($this->blacklist->has($payload));
    }

    /** @test */
    public function it_should_remove_a_token_from_the_blacklist()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);

        $this->storage->shouldReceive('destroy')->with('foobar')->andReturn(true);
        $this->assertTrue($this->blacklist->remove($payload));
    }

    /** @test */
    public function it_should_set_a_custom_unique_key_for_the_blacklist()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);

        $this->storage->shouldReceive('get')->with(1)->once()->andReturn(['valid_until' => $this->testNowTimestamp]);

        $this->assertTrue($this->blacklist->setKey('sub')->has($payload));
        $this->assertSame(1, $this->blacklist->getKey($payload));
    }

    /** @test */
    public function it_should_empty_the_blacklist()
    {
        $this->storage->shouldReceive('flush');
        $this->assertTrue($this->blacklist->clear());
    }

    /** @test */
    public function it_should_set_and_get_the_blacklist_grace_period()
    {
        $this->assertInstanceOf(Blacklist::class, $this->blacklist->setGracePeriod(15));
        $this->assertSame(15, $this->blacklist->getGracePeriod());
    }

    /** @test */
    public function it_should_set_and_get_the_blacklist_refresh_ttl()
    {
        $this->assertInstanceOf(Blacklist::class, $this->blacklist->setRefreshTTL(15));
        $this->assertSame(15, $this->blacklist->getRefreshTTL());

        $this->blacklist->setRefreshTTL(null);
        $this->assertNull($this->blacklist->getRefreshTTL());
    }

    /** @test */
    public function it_should_build_a_prefixed_subject_key()
    {
        $claims = [
            'sub' => 42,
            'prv' => 'provider-hash',
        ];

        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('hasKey')->andReturnUsing(function ($key) use ($claims) {
            return array_key_exists($key, $claims);
        });
        $payload->shouldReceive('offsetGet')->andReturnUsing(function ($key) use ($claims) {
            return $claims[$key] ?? null;
        });

        $this->assertSame(
            'logout_all_devices:'.sha1(json_encode(['sub' => '42', 'prv' => 'provider-hash'])),
            $this->blacklist->getSubjectKey($payload)
        );
    }

    /** @test */
    public function it_should_throw_an_exception_when_building_a_subject_key_without_sub()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('The token does not contain the required subject claim.');

        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('hasKey')->with('sub')->andReturn(false);

        $this->blacklist->getSubjectKey($payload);
    }

    /** @test */
    public function it_should_add_a_subject_revocation_cutoff_with_expiring_ttl()
    {
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

        $key = 'logout_all_devices:'.sha1(json_encode(['sub' => '42', 'prv' => 'provider-hash']));

        $this->storage->shouldReceive('destroy')->once()->with($key)->andReturn(true);
        $this->storage->shouldReceive('add')
            ->once()
            ->with($key, ['cutoff' => $this->testNowTimestamp], 201)
            ->andReturn(true);

        $this->assertTrue(
            $this->blacklist
                ->setTTL(60)
                ->setRefreshTTL(200)
                ->setLogoutAllDevicesTTL(null)
                ->addSubject($payload)
        );
    }

    /** @test */
    public function it_should_add_a_subject_revocation_cutoff_with_ttl_plus_one_when_token_ttl_is_longer_than_refresh_ttl()
    {
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

        $key = 'logout_all_devices:'.sha1(json_encode(['sub' => '42', 'prv' => 'provider-hash']));

        $this->storage->shouldReceive('destroy')->once()->with($key)->andReturn(true);
        $this->storage->shouldReceive('add')
            ->once()
            ->with($key, ['cutoff' => $this->testNowTimestamp], 1441)
            ->andReturn(true);

        $this->assertTrue(
            $this->blacklist
                ->setTTL(1440)
                ->setRefreshTTL(60)
                ->setLogoutAllDevicesTTL(null)
                ->addSubject($payload)
        );
    }

    /** @test */
    public function it_should_add_a_subject_revocation_cutoff_forever_when_refresh_ttl_is_null()
    {
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

        $key = 'logout_all_devices:'.sha1(json_encode(['sub' => '42', 'prv' => 'provider-hash']));

        $this->storage->shouldReceive('destroy')->once()->with($key)->andReturn(true);
        $this->storage->shouldReceive('forever')
            ->once()
            ->with($key, ['cutoff' => $this->testNowTimestamp]);
        $this->storage->shouldReceive('add')->never();

        $this->assertTrue(
            $this->blacklist
                ->setTTL(60)
                ->setRefreshTTL(null)
                ->setLogoutAllDevicesTTL(null)
                ->addSubject($payload)
        );
    }

    /** @test */
    public function it_should_add_a_subject_revocation_cutoff_forever_when_token_ttl_is_null()
    {
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

        $key = 'logout_all_devices:'.sha1(json_encode(['sub' => '42', 'prv' => 'provider-hash']));

        $this->storage->shouldReceive('destroy')->once()->with($key)->andReturn(true);
        $this->storage->shouldReceive('forever')
            ->once()
            ->with($key, ['cutoff' => $this->testNowTimestamp]);
        $this->storage->shouldReceive('add')->never();

        $this->assertTrue(
            $this->blacklist
                ->setTTL(null)
                ->setRefreshTTL(60)
                ->setLogoutAllDevicesTTL(5000)
                ->addSubject($payload)
        );
    }

    /** @test */
    public function it_should_check_whether_a_subject_has_been_revoked_based_on_cutoff()
    {
        $claims = [
            'sub' => '42',
            'prv' => 'provider-hash',
            'iat' => 100,
        ];

        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('hasKey')->andReturnUsing(function ($key) use (&$claims) {
            return array_key_exists($key, $claims);
        });
        $payload->shouldReceive('offsetGet')->andReturnUsing(function ($key) use (&$claims) {
            return $claims[$key] ?? null;
        });

        $key = 'logout_all_devices:'.sha1(json_encode(['sub' => '42', 'prv' => 'provider-hash']));
        $this->storage->shouldReceive('get')->with($key)->andReturn(['cutoff' => 100], ['cutoff' => 99], ['cutoff' => 101]);

        $this->assertTrue($this->blacklist->hasSubject($payload));
        $this->assertFalse($this->blacklist->hasSubject($payload));

        unset($claims['iat']);
        $this->assertTrue($this->blacklist->hasSubject($payload));
    }

    /** @test */
    public function it_should_return_false_when_subject_revocation_cannot_be_matched()
    {
        $claims = [
            'sub' => '42',
        ];

        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('hasKey')->andReturnUsing(function ($key) use (&$claims) {
            return array_key_exists($key, $claims);
        });
        $payload->shouldReceive('offsetGet')->andReturnUsing(function ($key) use (&$claims) {
            return $claims[$key] ?? null;
        });

        $key = 'logout_all_devices:'.sha1(json_encode(['sub' => '42', 'prv' => null]));

        $this->storage->shouldReceive('get')->once()->with($key)->andReturn(null);

        $this->assertFalse($this->blacklist->hasSubject($payload));

        unset($claims['sub']);
        $this->assertFalse($this->blacklist->hasSubject($payload));
    }

    /** @test */
    public function it_should_set_and_get_the_logout_all_devices_ttl()
    {
        $this->assertInstanceOf(Blacklist::class, $this->blacklist->setRefreshTTL(120)->setLogoutAllDevicesTTL(150));
        $this->assertSame(150, $this->blacklist->getLogoutAllDevicesTTL());

        $this->blacklist->setLogoutAllDevicesTTL(100);
        $this->assertSame(121, $this->blacklist->getLogoutAllDevicesTTL());

        $this->blacklist->setLogoutAllDevicesTTL(null);
        $this->assertSame(121, $this->blacklist->getLogoutAllDevicesTTL());
    }

    /** @test */
    public function it_should_include_the_leeway_minutes_in_the_logout_all_devices_ttl_floor()
    {
        $this->assertSame(
            71,
            $this->blacklist
                ->setTTL(60)
                ->setRefreshTTL(60)
                ->setLeeway(600)
                ->setLogoutAllDevicesTTL(null)
                ->getLogoutAllDevicesTTL()
        );
    }
}
