<?php

namespace Tests\Feature\Console;

use App\Services\EmailRiskRefreshService;
use Illuminate\Support\Facades\Artisan;
use Mockery;
use Tests\TestCase;

class RefreshEmailRiskBlacklistCommandTest extends TestCase
{
    /**
     * 默认启用邮件风控，隔离命令开关用例。
     */
    protected function setUp(): void
    {
        parent::setUp();
        config(['v2board.email_risk_blacklist_enable' => 1]);
    }

    /**
     * 验证四种预期结果都只调用一次服务并输出聚合计数。
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
        $service = Mockery::mock(EmailRiskRefreshService::class);
        $service->shouldReceive('refreshScheduled')->once()->withNoArgs()->andReturn($status);
        $this->app->instance(EmailRiskRefreshService::class, $service);

        $this->artisan('risk:refresh-email-blacklist')
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
     * 验证关闭邮件风控时命令静默成功且不调用刷新服务。
     */
    public function testDisabledCommandSkipsServiceAndProducesNoOutput(): void
    {
        config(['v2board.email_risk_blacklist_enable' => 0]);
        $service = Mockery::mock(EmailRiskRefreshService::class);
        $service->shouldNotReceive('refreshScheduled');
        $this->app->instance(EmailRiskRefreshService::class, $service);

        $this->assertSame(0, Artisan::call('risk:refresh-email-blacklist'));
        $this->assertSame('', Artisan::output());
    }

    /**
     * 验证锁内关闭标记跳过时命令静默成功。
     */
    public function testMarkerSkipProducesNoOutput(): void
    {
        $service = Mockery::mock(EmailRiskRefreshService::class);
        $service->shouldReceive('refreshScheduled')->once()->withNoArgs()->andReturnNull();
        $this->app->instance(EmailRiskRefreshService::class, $service);

        $this->assertSame(0, Artisan::call('risk:refresh-email-blacklist'));
        $this->assertSame('', Artisan::output());
    }

    /**
     * 验证内核为 IP 和邮件刷新声明错峰非重叠日调度。
     */
    public function testKernelDeclaresExactStaggeredDailySchedules(): void
    {
        $source = file_get_contents(app_path('Console/Kernel.php'));

        $this->assertIsString($source);
        $this->assertStringContainsString(
            '$schedule->command(\'risk:refresh-ip-blacklist\')->dailyAt(\'1:30\')->withoutOverlapping();',
            $source
        );
        $this->assertStringContainsString(
            '$schedule->command(\'risk:refresh-email-blacklist\')->dailyAt(\'1:45\')->withoutOverlapping();',
            $source
        );
    }
}
