<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Throwable;

class DatabaseCircuit
{
    public function handle($request, Closure $next)
    {
        $key = $this->key();
        $circuit = $this->readCircuit($key);

        try {
            if ($circuit['blocked']) {
                return $this->unavailable();
            }
            $response = $this->dispatch($request, $next, $circuit['cache'] && $circuit['lock']);
            $this->updateCircuit($key, $circuit, $request->attributes->get('database_connection_failed', false));
            return $response;
        } finally {
            if ($circuit['lock']) {
                $this->release($circuit['lock']);
            }
        }
    }

    private function readCircuit(string $key): array
    {
        $circuit = ['cache' => null, 'lock' => null, 'retry_at' => null, 'expires_at' => null, 'blocked' => false];
        try {
            $cache = Cache::store('redis');
            $circuit['cache'] = $cache;
            $circuit['retry_at'] = $cache->get($key);
            if ($circuit['retry_at'] === null) {
                return $circuit;
            }
            if ($circuit['retry_at'] > time()) {
                $circuit['blocked'] = true;
                return $circuit;
            }
            $lock = $cache->lock($key . ':probe', 30);
            if (!$lock->get()) {
                $circuit['blocked'] = true;
                return $circuit;
            }
            $circuit['lock'] = $lock;
            $circuit['expires_at'] = now()->addSeconds(30);
            // A concurrent failure may restart the cooldown while we acquire the lock.
            $circuit['retry_at'] = $cache->get($key);
            $circuit['blocked'] = $circuit['retry_at'] !== null && $circuit['retry_at'] > time();
        } catch (Throwable $ignored) {
            // Redis unavailable: allow normal request handling.
            $circuit['cache'] = null;
            $circuit['blocked'] = false;
        }
        return $circuit;
    }

    private function dispatch($request, Closure $next, bool $probe)
    {
        try {
            if ($probe) {
                DB::select('SELECT 1');
            }
            return $next($request);
        } catch (Throwable $exception) {
            $handler = app(ExceptionHandler::class);
            $handler->report($exception);
            return $handler->render($request, $exception);
        }
    }

    private function updateCircuit(string $key, array $circuit, bool $connectionFailed): void
    {
        $cache = $circuit['cache'];
        if (!$cache) {
            return;
        }
        try {
            if ($connectionFailed) {
                $cache->forever($key, time() + 5);
            } elseif ($circuit['lock'] && now()->lt($circuit['expires_at'])
                && $cache->get($key) === $circuit['retry_at']) {
                $cache->forget($key);
            }
        } catch (Throwable $ignored) {
            // Cache failure must not replace the application response.
        }
    }

    private function key(): string
    {
        $connection = config('database.default');
        $database = config("database.connections.{$connection}");
        return 'database-circuit:' . sha1(json_encode([$connection, $database['host'] ?? '', $database['port'] ?? '', $database['database'] ?? '']));
    }

    private function unavailable()
    {
        return response()->json(['message' => 'Database temporarily unavailable'], 503)->header('Retry-After', '5');
    }

    private function release($lock): void
    {
        try {
            $lock->release();
        } catch (Throwable $ignored) {
            // The lock expires automatically if Redis cannot be reached.
        }
    }
}
