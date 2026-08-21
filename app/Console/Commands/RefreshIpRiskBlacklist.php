<?php

namespace App\Console\Commands;

use App\Services\IpRiskRefreshService;
use Illuminate\Console\Command;

class RefreshIpRiskBlacklist extends Command
{
    protected $signature = 'risk:refresh-ip-blacklist';

    protected $description = '刷新 IP 风险黑名单订阅';

    private $refreshService;

    /**
     * 注入 IP 风险黑名单刷新服务。
     */
    public function __construct(IpRiskRefreshService $refreshService)
    {
        parent::__construct();
        $this->refreshService = $refreshService;
    }

    /**
     * 执行刷新并输出不含来源地址的结果计数。
     */
    public function handle(): int
    {
        $status = $this->refreshService->refresh();
        $this->info(sprintf(
            'outcome=%s sources=%d refreshed=%d failed=%d retained=%d rules=%d invalid=%d',
            $status['outcome'],
            $status['source_count'],
            $status['refreshed_count'],
            $status['failed_count'],
            $status['retained_count'],
            $status['rule_count'],
            $status['invalid_line_count']
        ));

        return self::SUCCESS;
    }
}
