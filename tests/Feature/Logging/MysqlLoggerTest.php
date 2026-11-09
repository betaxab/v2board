<?php

namespace Tests\Feature\Logging;

use App\Logging\MysqlLogger;
use App\Logging\MysqlLoggerHandler;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Monolog\Formatter\FormatterInterface;
use Monolog\Logger;
use PDOException;
use Tests\TestCase;

class MysqlLoggerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config([
            'database.default' => 'sqlite',
            'database.connections.sqlite' => [
                'driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '',
                'foreign_key_constraints' => false,
            ],
        ]);
        DB::purge('sqlite');
        DB::reconnect('sqlite');
        Schema::create('v2_log', function (Blueprint $table): void {
            $table->increments('id');
            foreach (['title', 'level', 'host', 'uri', 'method', 'ip', 'data', 'context'] as $column) {
                $table->text($column)->nullable();
            }
            $table->integer('created_at');
            $table->integer('updated_at');
        });
        $this->app->instance('request', Request::create('/api/v1/example?token=secret-token&node_id=2'));
    }

    protected function tearDown(): void
    {
        DB::disconnect('sqlite');
        parent::tearDown();
    }

    public function testNormalLogsStillWriteToDatabase(): void
    {
        $this->logger()->info('Normal message', ['operation' => 'test']);
        $log = DB::table('v2_log')->first();
        $this->assertSame('Normal message', $log->title);
        $this->assertSame('INFO', $log->level);
        $this->assertSame(['operation' => 'test'], json_decode($log->context, true));
    }

    public function testDatabaseExceptionWritesOnlyFixedMessageWithoutFormattingOrQuerying(): void
    {
        $exception = new QueryException('insert into test values (?)', ['large payload'], new PDOException('Connection refused', 2002));
        $fallback = \Mockery::mock();
        Log::shouldReceive('channel')->once()->with('daily')->andReturn($fallback);
        $fallback->shouldReceive('error')->once()->with('Database failure');
        $formatter = \Mockery::mock(FormatterInterface::class);
        $formatter->shouldNotReceive('format');
        $handler = new MysqlLoggerHandler();
        $handler->setFormatter($formatter);
        $queries = 0;
        DB::listen(function () use (&$queries) { $queries++; });
        (new Logger('test', [$handler]))->error($exception->getMessage(), ['exception' => $exception]);
        $this->assertSame(0, $queries);
    }

    public function testFailedLogInsertWritesOnlyFixedMessage(): void
    {
        Schema::drop('v2_log');
        $fallback = \Mockery::mock();
        Log::shouldReceive('channel')->once()->with('daily')->andReturn($fallback);
        $fallback->shouldReceive('error')->once()->with('Database failure');
        $this->logger()->error('Original error', ['operation' => 'test']);
    }

    public function testUnwritableFileFallsBackToPhpErrorLog(): void
    {
        Log::shouldReceive('channel')->with('daily')->andThrow(new \RuntimeException('File not writable'));
        $path = tempnam(sys_get_temp_dir(), 'v2board-log-test-');
        $previous = ini_set('error_log', $path);
        try {
            $this->logger()->error('Connection refused', ['exception' => new PDOException('Connection refused', 2002)]);
            $contents = file_get_contents($path);
            $this->assertStringContainsString('Database failure', $contents);
            $this->assertStringNotContainsString('Connection refused', $contents);
        } finally {
            ini_set('error_log', $previous);
            unlink($path);
        }
    }

    private function logger(): Logger
    {
        return (new MysqlLogger())([]);
    }
}
