<?php

namespace Tests\Feature\Console;

use App\Services\IpRiskRefreshService;
use Mockery;
use Tests\TestCase;

class RefreshIpRiskBlacklistCommandTest extends TestCase
{
    /**
     * 验证四种预期结果都只调用一次服务并以成功状态退出。
     *
     * @dataProvider outcomeProvider
     */
    public function testCommandDelegatesOnceAndReportsOnlyOutcomeCounts(string $outcome): void
    {
        $status = [
            'version' => 1,
            'outcome' => $outcome,
            'started_at' => 100,
            'completed_at' => 101,
            'source_count' => 2,
            'refreshed_count' => 1,
            'failed_count' => 1,
            'retained_count' => 1,
            'rule_count' => 8,
            'invalid_line_count' => 3,
            'failed_sources' => [
                ['source' => 'https://secret.example/list', 'error' => 'http_5xx'],
            ],
        ];
        $service = Mockery::mock(IpRiskRefreshService::class);
        $service->shouldReceive('refresh')->once()->withNoArgs()->andReturn($status);
        $this->app->instance(IpRiskRefreshService::class, $service);

        $this->artisan('risk:refresh-ip-blacklist')
            ->expectsOutput(sprintf(
                'outcome=%s sources=2 refreshed=1 failed=1 retained=1 rules=8 invalid=3',
                $outcome
            ))
            ->doesntExpectOutput('https://secret.example/list')
            ->assertExitCode(0);
    }

    /**
     * 提供刷新服务的四种正常完成结果。
     */
    public function outcomeProvider(): array
    {
        return [
            'success' => ['success'],
            'partial failure' => ['partial_failure'],
            'total failure' => ['total_failure'],
            'not configured' => ['not_configured'],
        ];
    }

    /**
     * 验证内核每天固定时间执行并阻止调度重叠。
     */
    public function testKernelDeclaresExactDailyNonOverlappingSchedule(): void
    {
        $source = file_get_contents(app_path('Console/Kernel.php'));

        $this->assertIsString($source);
        $this->assertStringContainsString(
            '$schedule->command(\'risk:refresh-ip-blacklist\')->dailyAt(\'1:30\')->withoutOverlapping();',
            $source
        );
    }
}
