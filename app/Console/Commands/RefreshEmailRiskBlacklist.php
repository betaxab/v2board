<?php

namespace App\Console\Commands;

use App\Services\EmailRiskRefreshService;
use Illuminate\Console\Command;

class RefreshEmailRiskBlacklist extends Command
{
    protected $signature = 'risk:refresh-email-blacklist';

    protected $description = '刷新邮件风险黑名单订阅';

    private $refreshService;

    /**
     * 注入邮件风险黑名单刷新服务。
     */
    public function __construct(EmailRiskRefreshService $refreshService)
    {
        parent::__construct();
        $this->refreshService = $refreshService;
    }

    /**
     * 启用时执行定时安全刷新并输出聚合计数。
     */
    public function handle(): int
    {
        if (!(bool)config('v2board.email_risk_blacklist_enable', 0)) {
            return self::SUCCESS;
        }

        $status = $this->refreshService->refreshScheduled();
        if ($status === null) {
            return self::SUCCESS;
        }

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
