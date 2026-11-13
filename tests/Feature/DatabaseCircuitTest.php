<?php

namespace Tests\Feature;

use App\Exceptions\Handler;
use App\Http\Middleware\DatabaseCircuit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

class DatabaseCircuitTest extends TestCase
{
    public function testOnlyConnectionErrorsTriggerTheCircuit(): void
    {
        $circuit = $this->app->make(Handler::class);
        foreach ([1040, 2002, 2003, 2006, 2013] as $code) {
            $exception = new \PDOException('Database error');
            $exception->errorInfo = ['HY000', $code, 'Database error'];
            $this->assertTrue($circuit->isDatabaseConnectionFailure($exception));
        }
        foreach ([1062, 1064, 1146, 1213] as $code) {
            $exception = new \PDOException('SQL error');
            $exception->errorInfo = ['42000', $code, 'SQL error'];
            $this->assertFalse($circuit->isDatabaseConnectionFailure($exception));
        }
        $this->assertFalse($circuit->isDatabaseConnectionFailure(new \RuntimeException('Connection refused')));
    }

    private function cache(bool $open, bool $cooldown = false)
    {
        $cache = \Mockery::mock();
        Cache::shouldReceive('store')->with('redis')->andReturn($cache);
        $cache->shouldReceive('get')->andReturn($open ? time() + ($cooldown ? 60 : -1) : null);
        return $cache;
    }

    public function testOpenCircuitRejectsWithoutDatabaseAccess(): void
    {
        $this->cache(true, true);
        DB::shouldReceive('select')->never();
        $response = (new DatabaseCircuit())->handle(Request::create('/'), function () {
            $this->fail('Open circuit must not execute the request');
        });
        $this->assertSame(503, $response->status());
        $this->assertSame('5', $response->headers->get('Retry-After'));
    }

    public function testRedisFailureAllowsTheRequestToProceed(): void
    {
        Cache::shouldReceive('store')->with('redis')->andThrow(new \RuntimeException('Redis unavailable'));
        $response = (new DatabaseCircuit())->handle(Request::create('/'), function () { return response('healthy'); });
        $this->assertSame(200, $response->status());
    }

    public function testOnlyLockOwnerCanProbeRecovery(): void
    {
        $cache = $this->cache(true);
        $lock = \Mockery::mock();
        $cache->shouldReceive('lock')->once()->with(\Mockery::type('string'), 30)->andReturn($lock);
        $lock->shouldReceive('get')->once()->andReturn(false);
        DB::shouldReceive('select')->never();
        $response = (new DatabaseCircuit())->handle(Request::create('/'), function () {
            $this->fail('Other requests must wait for the probe');
        });
        $this->assertSame(503, $response->status());
    }

    public function testRecoveryProbeChecksDatabaseAndClearsTheCircuit(): void
    {
        $cache = $this->cache(true);
        $lock = \Mockery::mock();
        $cache->shouldReceive('lock')->once()->andReturn($lock);
        $lock->shouldReceive('get')->once()->andReturn(true);
        DB::shouldReceive('select')->once()->with('SELECT 1')->andReturn([]);
        $cache->shouldReceive('forget')->once()->ordered()->andReturn(true);
        $lock->shouldReceive('release')->once()->ordered()->andReturn(true);
        $response = (new DatabaseCircuit())->handle(Request::create('/'), function () { return response('healthy'); });
        $this->assertSame(200, $response->status());
    }

    public function testConnectionFailureTripsTheCircuit(): void
    {
        $cache = $this->cache(false);
        $cache->shouldReceive('forever')->once()->with(\Mockery::type('string'), \Mockery::on(function ($value) { return $value >= time() + 4 && $value <= time() + 5; }));
        $cache->shouldReceive('put')->never();
        $request = Request::create('/');
        $response = (new DatabaseCircuit())->handle($request, function () { throw new \PDOException('Connection refused', 2002); });
        $this->assertSame(503, $response->status());
        $this->assertTrue($request->attributes->get('database_connection_failed'));
    }

    public function testFailedProbeReopensCircuitAndReleasesLock(): void
    {
        $cache = $this->cache(true);
        $lock = \Mockery::mock();
        $cache->shouldReceive('lock')->once()->andReturn($lock);
        $lock->shouldReceive('get')->once()->andReturn(true);
        DB::shouldReceive('select')->once()->andThrow(new \PDOException('Connection refused', 2002));
        $cache->shouldReceive('forever')->once();
        $lock->shouldReceive('release')->once()->andReturn(true);
        $cache->shouldReceive('forget')->never();
        $response = (new DatabaseCircuit())->handle(Request::create('/'), function () { $this->fail('Probe failed'); });
        $this->assertSame(503, $response->status());
    }

    public function testExpiredProbeDoesNotClearTheCircuit(): void
    {
        $cache = $this->cache(true);
        $lock = \Mockery::mock();
        $cache->shouldReceive('lock')->once()->andReturn($lock);
        $lock->shouldReceive('get')->once()->andReturn(true);
        DB::shouldReceive('select')->once()->andReturnUsing(function () {
            \Carbon\Carbon::setTestNow(now()->addSeconds(31));
            return [];
        });
        $lock->shouldReceive('release')->once()->andReturn(false);
        $cache->shouldReceive('forget')->never();
        try {
            (new DatabaseCircuit())->handle(Request::create('/'), function () { return response('healthy'); });
        } finally {
            \Carbon\Carbon::setTestNow();
        }
    }
    public function testCooldownRestartedDuringLockAcquisitionReleasesLockAndRejects(): void
    {
        $cache = \Mockery::mock();
        Cache::shouldReceive('store')->with('redis')->andReturn($cache);
        $cache->shouldReceive('get')->twice()->andReturn(time() - 1, time() + 5);
        $lock = \Mockery::mock();
        $cache->shouldReceive('lock')->once()->andReturn($lock);
        $lock->shouldReceive('get')->once()->andReturn(true);
        $lock->shouldReceive('release')->once()->andReturn(true);
        DB::shouldReceive('select')->never();
        $response = (new DatabaseCircuit())->handle(Request::create('/'), function () {
            $this->fail('Cooldown was restarted');
        });
        $this->assertSame(503, $response->status());
    }

    public function testProbePreservesANewerFailureState(): void
    {
        $cache = \Mockery::mock();
        Cache::shouldReceive('store')->with('redis')->andReturn($cache);
        $previous = time() - 1;
        $cache->shouldReceive('get')->times(3)->andReturn($previous, $previous, time() + 5);
        $lock = \Mockery::mock();
        $cache->shouldReceive('lock')->once()->andReturn($lock);
        $lock->shouldReceive('get')->once()->andReturn(true);
        DB::shouldReceive('select')->once()->with('SELECT 1')->andReturn([]);
        $cache->shouldReceive('forget')->never();
        $lock->shouldReceive('release')->once()->andReturn(true);
        $response = (new DatabaseCircuit())->handle(Request::create('/'), function () { return response('healthy'); });
        $this->assertSame(200, $response->status());
    }

}
