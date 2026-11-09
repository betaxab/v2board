<?php
namespace App\Logging;

use Illuminate\Support\Facades\Log;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Logger;
use App\Models\Log as LogModel;

class MysqlLoggerHandler extends AbstractProcessingHandler
{
    public function __construct($level = Logger::DEBUG, bool $bubble = true)
    {
        parent::__construct($level, $bubble);
    }

    public function handle(array $record): bool
    {
        if (!$this->isHandling($record)) {
            return false;
        }
        // Skip formatting and database writes for database exceptions.
        if (($record['context']['exception'] ?? null) instanceof \PDOException) {
            $this->logDatabaseFailure();
            return !$this->bubble;
        }
        return parent::handle($record);
    }

    protected function write(array $record): void
    {
        try{
            if(isset($record['context']['exception']) && is_object($record['context']['exception'])){
                $record['context']['exception'] = (array)$record['context']['exception'];
            }
            $record['request_data'] = request()->all() ??[];
            $log = [
                'title' => $record['message'],
                'level' => $record['level_name'],
                'host' => $record['request_host'] ?? request()->getSchemeAndHttpHost(),
                'uri' => $record['request_uri'] ?? request()->getRequestUri(),
                'method' => $record['request_method'] ?? request()->getMethod(),
                'ip' => request()->getClientIp(),
                'data' => json_encode($record['request_data']) ,
                'context' => isset($record['context']) ? json_encode($record['context']) : '',
                'created_at' => $record['datetime']->getTimestamp(),
                'updated_at' => $record['datetime']->getTimestamp(),
            ];

            LogModel::insert(
                $log
            );
        } catch (\Throwable $e) {
            $this->logDatabaseFailure();
        }
    }

    private function logDatabaseFailure(): void
    {
        try {
            Log::channel('daily')->error('Database failure');
        } catch (\Throwable $e) {
            @error_log('Database failure');
        }
    }

}
