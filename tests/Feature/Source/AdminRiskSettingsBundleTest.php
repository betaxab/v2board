<?php

namespace Tests\Feature\Source;

use Tests\TestCase;

class AdminRiskSettingsBundleTest extends TestCase
{
    /**
     * 验证编译包包含独立风控标签和全部控件。
     */
    public function testBundleContainsDedicatedRiskTabAndControls(): void
    {
        $source = $this->bundleSource();

        $this->assertStringContainsString('tab: "\u98ce\u63a7"', $source);
        $this->assertStringContainsString('key: "risk"', $source);
        $this->assertStringContainsString('title: "\u542f\u7528IP\u9ed1\u540d\u5355"', $source);
        $this->assertStringContainsString('title: "\u9ed1\u540d\u5355\u8ba2\u9605\u5730\u5740"', $source);
        $this->assertStringContainsString('title: "IP/CIDR\u4f8b\u5916"', $source);
        $this->assertStringContainsString('ip_risk_blacklist_enable', $source);
        $this->assertStringContainsString('ip_risk_blacklist_urls', $source);
        $this->assertStringContainsString('ip_risk_exception_rules', $source);
    }

    /**
     * 验证风控分组进入模型状态和现有分组保存路径。
     */
    public function testBundleStoresAndSavesCompleteRiskGroup(): void
    {
        $source = $this->bundleSource();

        $this->assertStringContainsString('risk: {},', $source);
        $this->assertStringContainsString(', R = e.risk', $source);
        $this->assertStringContainsString('parentKey: e', $source);
        $this->assertStringContainsString('t[n]', $source);
        $this->assertStringContainsString('/config/save', $source);
    }

    /**
     * 验证风控开关读取整数并持久化为零或一。
     */
    public function testRiskSwitchUsesIntegerPersistence(): void
    {
        $snippet = $this->snippetAround($this->bundleSource(), 'ip_risk_blacklist_enable', 300);

        $this->assertStringContainsString('checked: parseInt(R.ip_risk_blacklist_enable)', $snippet);
        $this->assertStringContainsString('this.set("risk", "ip_risk_blacklist_enable", e ? 1 : 0)', $snippet);
    }

    /**
     * 验证风控文本域直接保存原始换行字符串。
     *
     * @dataProvider riskTextareaProvider
     */
    public function testRiskTextareasPreserveRawNewlineStrings(string $field): void
    {
        $snippet = $this->snippetAround($this->bundleSource(), $field, 420);

        $this->assertStringContainsString("defaultValue: R.{$field}", $snippet);
        $this->assertStringContainsString("this.set(\"risk\", \"{$field}\", e.target.value)", $snippet);
        $this->assertStringNotContainsString('.split(', $snippet);
        $this->assertStringNotContainsString('.map(', $snippet);
    }

    /**
     * 提供两个需要保留换行的风控文本字段。
     */
    public function riskTextareaProvider(): array
    {
        return [
            'subscription URLs' => ['ip_risk_blacklist_urls'],
            'exception rules' => ['ip_risk_exception_rules'],
        ];
    }

    /**
     * 验证现有模型按父分组保存并重新获取配置。
     */
    public function testExistingEffectsSaveAndRefetchGroupedRiskState(): void
    {
        $source = $this->bundleSource();
        $saveSnippet = $this->snippetAround($source, '/config/save', 1400);
        $fetchSnippet = $this->snippetAround($source, '/config/fetch', 2600);

        $this->assertStringContainsString('var n = e.parentKey', $saveSnippet);
        $this->assertStringContainsString('/config/save", a()({}, t[n])', $saveSnippet);
        $this->assertStringContainsString('type: "fetch"', $saveSnippet);
        $this->assertStringContainsString('payload: a()({}, o.data)', $fetchSnippet);
    }

    /**
     * 验证后端首条字段错误通过共享通知展示。
     */
    public function testBackendFieldErrorUsesExistingFailureNotification(): void
    {
        $snippet = $this->snippetAround($this->bundleSource(), 'Object.values(s.errors)[0][0]', 320);

        $this->assertStringContainsString('description: Object.values(s.errors)[0][0]', $snippet);
        $this->assertStringContainsString('msg: Object.values(s.errors)[0][0]', $snippet);
    }

    /**
     * 验证风控页展示五种刷新状态、全部计数和最后运行时间。
     */
    public function testBundleRendersCompleteLatestRefreshStatusSummary(): void
    {
        $source = $this->bundleSource();
        $snippet = $this->snippetAround($source, '"\\u6700\\u65b0\\u5237\\u65b0\\u72b6\\u6001"', 2800);
        $definition = $this->snippetAround($source, 'ip_risk_refresh_status', 1200);

        $this->assertStringContainsString('ip_risk_refresh_status', $source);
        $this->assertStringContainsString('not_run', $definition);
        $this->assertStringContainsString('not_configured', $definition);
        $this->assertStringContainsString('success', $definition);
        $this->assertStringContainsString('partial_failure', $definition);
        $this->assertStringContainsString('total_failure', $definition);
        $this->assertStringContainsString('"\\u5c1a\\u672a\\u8fd0\\u884c"', $definition);
        $this->assertStringContainsString('"\\u672a\\u914d\\u7f6e"', $definition);
        $this->assertStringContainsString('"\\u6210\\u529f"', $definition);
        $this->assertStringContainsString('"\\u90e8\\u5206\\u5931\\u8d25"', $definition);
        $this->assertStringContainsString('"\\u5168\\u90e8\\u5931\\u8d25"', $definition);
        $this->assertStringContainsString('completed_at', $snippet);
        foreach ([
            'source_count',
            'refreshed_count',
            'failed_count',
            'retained_count',
            'rule_count',
            'invalid_line_count',
        ] as $field) {
            $this->assertStringContainsString($field, $snippet);
        }
    }

    /**
     * 验证界面只使用后端脱敏来源且不提供手动刷新入口。
     */
    public function testBundleUsesSanitizedFailedSourcesWithoutManualRefreshControl(): void
    {
        $source = $this->bundleSource();
        $snippet = $this->snippetAround($source, '"\\u6700\\u65b0\\u5237\\u65b0\\u72b6\\u6001"', 2800);
        $definition = $this->snippetAround($source, 'ip_risk_refresh_status', 1200);

        $this->assertStringContainsString('failed_sources', $definition);
        $this->assertStringContainsString('e.source', $snippet);
        $this->assertStringContainsString('e.error', $snippet);
        $this->assertStringNotContainsString('new URL(', $snippet);
        $this->assertStringNotContainsString('risk:refresh-ip-blacklist', $source);
        $this->assertStringNotContainsString('/config/refresh', $source);
        $this->assertStringNotContainsString('manual_refresh', $source);
    }

    /**
     * 读取部署中的管理端编译包。
     */
    private function bundleSource(): string
    {
        $source = file_get_contents(base_path('public/assets/admin/umi.js'));
        $this->assertIsString($source);

        return $source;
    }

    /**
     * 截取字段附近的编译代码以约束局部处理行为。
     */
    private function snippetAround(string $source, string $needle, int $radius): string
    {
        $position = strpos($source, $needle);
        $this->assertNotFalse($position, "编译包缺少标记：{$needle}");
        $start = max(0, $position - $radius);

        return substr($source, $start, strlen($needle) + ($radius * 2));
    }
}
