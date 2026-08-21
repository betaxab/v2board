<?php

namespace Tests\Feature\Admin;

use App\Http\Controllers\V1\Admin\ConfigController;
use App\Http\Requests\Admin\ConfigSave;
use App\Services\IpRiskRefreshService;
use App\Utils\CacheKey;
use Illuminate\Http\Request;
use Illuminate\Routing\Redirector;
use Illuminate\Support\Facades\Cache;
use Illuminate\Validation\ValidationException;
use Tests\TestCase;

class ConfigRiskControlTest extends TestCase
{
    /**
     * 重置风险状态缓存以隔离每个配置测试。
     */
    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        config(['cache.default' => 'array']);
    }

    /**
     * 验证有效风险配置通过校验且保留内部换行。
     */
    public function testValidRiskSettingsValidateWithoutChangingNewlines(): void
    {
        $payload = [
            'ip_risk_blacklist_enable' => 1,
            'ip_risk_blacklist_urls' => "https://one.example/list.txt\nhttp://two.example/rules",
            'ip_risk_exception_rules' => "192.0.2.7\n2001:db8::/32",
        ];

        $this->assertSame($payload, $this->validateRequest($payload)->validated());
    }

    /**
     * 验证显式清空的文本配置仍保留在校验结果中。
     */
    public function testPresentNullTextareasNormalizeToEmptyStrings(): void
    {
        $request = $this->validateRequest([
            'ip_risk_blacklist_enable' => 0,
            'ip_risk_blacklist_urls' => null,
            'ip_risk_exception_rules' => null,
        ]);

        $this->assertSame([
            'ip_risk_blacklist_enable' => 0,
            'ip_risk_blacklist_urls' => '',
            'ip_risk_exception_rules' => '',
        ], $request->validated());
    }

    /**
     * 验证风险配置按独立分组和稳定类型返回。
     */
    public function testRiskFetchReturnsOnlyRequestedGroupWithStableTypes(): void
    {
        config([
            'v2board.ip_risk_blacklist_enable' => '1',
            'v2board.ip_risk_blacklist_urls' => "https://one.example/list.txt\nhttps://two.example/list.txt",
            'v2board.ip_risk_exception_rules' => "192.0.2.7\n2001:db8::/32",
        ]);

        $this->assertSame([
            'data' => [
                'risk' => [
                    'ip_risk_blacklist_enable' => 1,
                    'ip_risk_blacklist_urls' => "https://one.example/list.txt\nhttps://two.example/list.txt",
                    'ip_risk_exception_rules' => "192.0.2.7\n2001:db8::/32",
                    'ip_risk_refresh_status' => $this->notRunStatus(),
                ],
            ],
        ], $this->fetchRiskGroup());
    }

    /**
     * 验证风险配置缺失时返回明确默认值。
     */
    public function testRiskFetchReturnsDeterministicDefaults(): void
    {
        $config = config('v2board', []);
        unset(
            $config['ip_risk_blacklist_enable'],
            $config['ip_risk_blacklist_urls'],
            $config['ip_risk_exception_rules']
        );
        config(['v2board' => $config]);

        $this->assertSame([
            'data' => [
                'risk' => [
                    'ip_risk_blacklist_enable' => 0,
                    'ip_risk_blacklist_urls' => '',
                    'ip_risk_exception_rules' => '',
                    'ip_risk_refresh_status' => $this->notRunStatus(),
                ],
            ],
        ], $this->fetchRiskGroup());
    }

    /**
     * 验证清空后的校验值重新读取时仍为空字符串。
     */
    public function testClearedValidatedValuesReopenAsEmptyStrings(): void
    {
        $validated = $this->validateRequest([
            'ip_risk_blacklist_enable' => 0,
            'ip_risk_blacklist_urls' => null,
            'ip_risk_exception_rules' => null,
        ])->validated();

        foreach ($validated as $key => $value) {
            config(["v2board.{$key}" => $value]);
        }

        $this->assertSame('', $this->fetchRiskGroup()['data']['risk']['ip_risk_blacklist_urls']);
        $this->assertSame('', $this->fetchRiskGroup()['data']['risk']['ip_risk_exception_rules']);
    }

    /**
     * 验证三个风险键均进入现有保存白名单。
     */
    public function testRiskKeysAreAdmittedByExistingSaveWhitelist(): void
    {
        $this->assertArrayHasKey('ip_risk_blacklist_enable', ConfigSave::RULES);
        $this->assertArrayHasKey('ip_risk_blacklist_urls', ConfigSave::RULES);
        $this->assertArrayHasKey('ip_risk_exception_rules', ConfigSave::RULES);

        $source = file_get_contents(app_path('Http/Controllers/V1/Admin/ConfigController.php'));
        $this->assertStringContainsString('foreach (ConfigSave::RULES as $k => $v)', $source);
        $this->assertStringContainsString('$config[$k] = $data[$k];', $source);
    }

    /**
     * 验证订阅地址允许 HTTP、HTTPS 和空白行。
     */
    public function testSubscriptionUrlsAcceptHttpHttpsAndBlankLines(): void
    {
        $value = "https://one.example/list.txt\n\n  http://two.example/rules  ";

        $this->assertSame($value, $this->validateRequest([
            'ip_risk_blacklist_urls' => $value,
        ])->validated()['ip_risk_blacklist_urls']);
    }

    /**
     * 验证非法订阅地址返回字段和行号且不回显内容。
     *
     * @dataProvider invalidSubscriptionUrlProvider
     */
    public function testInvalidSubscriptionUrlReturnsLineSpecificError(string $invalidUrl): void
    {
        $errors = $this->validationErrors([
            'ip_risk_blacklist_urls' => "https://valid.example/list.txt\n\n{$invalidUrl}",
        ]);

        $this->assertSame('黑名单订阅地址第 3 行格式不正确', $errors['ip_risk_blacklist_urls'][0]);
        $this->assertStringNotContainsString($invalidUrl, $errors['ip_risk_blacklist_urls'][0]);
    }

    /**
     * 提供禁用协议、缺失主机和畸形订阅地址。
     */
    public function invalidSubscriptionUrlProvider(): array
    {
        return [
            'FTP scheme' => ['ftp://example.com/list.txt'],
            'file scheme' => ['file:///etc/passwd'],
            'gopher scheme' => ['gopher://example.com/1'],
            'missing host' => ['http:///list.txt'],
            'malformed URL' => ['not-a-url'],
        ];
    }

    /**
     * 验证非法例外规则返回字段和行号且不回显内容。
     *
     * @dataProvider invalidExceptionRuleProvider
     */
    public function testInvalidExceptionRuleReturnsLineSpecificError(string $invalidRule): void
    {
        $errors = $this->validationErrors([
            'ip_risk_exception_rules' => "192.0.2.7\n{$invalidRule}",
        ]);

        $this->assertSame('IP/CIDR例外第 2 行格式不正确', $errors['ip_risk_exception_rules'][0]);
        $this->assertStringNotContainsString($invalidRule, $errors['ip_risk_exception_rules'][0]);
    }

    /**
     * 提供畸形地址、CIDR 分隔符和前缀范围用例。
     */
    public function invalidExceptionRuleProvider(): array
    {
        return [
            'malformed exact IP' => ['999.0.0.1'],
            'multiple slashes' => ['192.0.2.0/24/1'],
            'non-decimal prefix' => ['192.0.2.0/x'],
            'IPv4 prefix overflow' => ['192.0.2.0/33'],
            'IPv6 prefix overflow' => ['2001:db8::/129'],
        ];
    }

    /**
     * 验证两个文本配置均拒绝超过固定上限的内容。
     *
     * @dataProvider oversizedTextareaProvider
     */
    public function testRiskTextareasRejectOversizedContent(string $field): void
    {
        $errors = $this->validationErrors([$field => str_repeat('a', 65536)]);

        $this->assertArrayHasKey($field, $errors);
    }

    /**
     * 提供两个受长度限制的风险文本字段。
     */
    public function oversizedTextareaProvider(): array
    {
        return [
            'subscription URLs' => ['ip_risk_blacklist_urls'],
            'exception rules' => ['ip_risk_exception_rules'],
        ];
    }

    /**
     * 验证规则构造为两个文本字段安全追加闭包。
     */
    public function testRulesConstructTextareaArraysWithValidationClosures(): void
    {
        $rules = (new ConfigSave())->rules();

        $this->assertIsArray($rules['ip_risk_blacklist_urls']);
        $this->assertIsArray($rules['ip_risk_exception_rules']);
        $this->assertCount(4, $rules['ip_risk_blacklist_urls']);
        $this->assertCount(4, $rules['ip_risk_exception_rules']);
        $this->assertInstanceOf(\Closure::class, $rules['ip_risk_blacklist_urls'][3]);
        $this->assertInstanceOf(\Closure::class, $rules['ip_risk_exception_rules'][3]);
    }

    /**
     * 验证订阅 URL 只按规范化集合的实际变化触发刷新。
     *
     * @dataProvider subscriptionUrlChangeProvider
     */
    public function testSubscriptionUrlChangesCompareNormalizedSets(
        string $before,
        string $after,
        bool $expected
    ): void {
        $service = new IpRiskRefreshService(null, null, function (): void {
        });

        $this->assertSame($expected, $service->hasSubscriptionUrlChanges($before, $after));
    }

    /**
     * 提供新增、删除、替换以及仅格式变化的 URL 集合。
     */
    public function subscriptionUrlChangeProvider(): array
    {
        return [
            'added URL' => ['https://one.example/list', "https://one.example/list\nhttps://two.example/list", true],
            'removed URL' => ["https://one.example/list\nhttps://two.example/list", 'https://one.example/list', true],
            'changed URL' => ['https://one.example/list', 'https://one.example/other', true],
            'reordered only' => ["https://one.example/list\nhttps://two.example/list", "https://two.example/list\nhttps://one.example/list", false],
            'duplicates only' => ['https://one.example/list', "https://one.example/list\nhttps://one.example/list", false],
            'blank lines only' => ["https://one.example/list\n", "\nhttps://one.example/list\n\n", false],
            'both empty' => ['', "\n\n", false],
        ];
    }

    /**
     * 验证缺少缓存时最新刷新状态稳定返回未运行结构。
     */
    public function testLatestStatusReturnsTypedNotRunShapeWhenCacheIsAbsent(): void
    {
        $service = new IpRiskRefreshService(null, null, function (): void {
        });

        $this->assertSame($this->notRunStatus(), $service->getLatestStatus());
    }

    /**
     * 验证风险分组读取缓存中的全部刷新结果类型且不发起网络请求。
     *
     * @dataProvider cachedOutcomeProvider
     */
    public function testRiskFetchReturnsTypedCachedRefreshOutcomes(string $outcome): void
    {
        $cached = [
            'version' => 1,
            'outcome' => $outcome,
            'started_at' => '100',
            'completed_at' => '101',
            'source_count' => '2',
            'refreshed_count' => '1',
            'failed_count' => '1',
            'retained_count' => '1',
            'rule_count' => '8',
            'invalid_line_count' => '3',
            'failed_sources' => [
                [
                    'source' => 'https://user:pass@example.test:8443/path/list?token=secret#fragment',
                    'error' => 'http_5xx',
                ],
            ],
        ];
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current'), $cached);

        $status = $this->fetchRiskGroup()['data']['risk']['ip_risk_refresh_status'];

        $this->assertSame($outcome, $status['outcome']);
        $this->assertSame(100, $status['started_at']);
        $this->assertSame(101, $status['completed_at']);
        $this->assertSame(2, $status['source_count']);
        $this->assertSame(8, $status['rule_count']);
        $this->assertSame('https://example.test:8443/path/list', $status['failed_sources'][0]['source']);
        $this->assertSame('http_5xx', $status['failed_sources'][0]['error']);
    }

    /**
     * 提供缓存可返回的四种已运行结果。
     */
    public function cachedOutcomeProvider(): array
    {
        return [
            'not configured' => ['not_configured'],
            'success' => ['success'],
            'partial failure' => ['partial_failure'],
            'total failure' => ['total_failure'],
        ];
    }

    /**
     * 验证控制器先持久化配置，再显式刷新新 URL 并保留保存结果。
     */
    public function testSaveSourcePersistsBeforeExplicitRefreshAndContainsFailureFallback(): void
    {
        $source = file_get_contents(app_path('Http/Controllers/V1/Admin/ConfigController.php'));
        $this->assertIsString($source);
        $persistPosition = strpos($source, 'File::put(');
        $refreshPosition = strpos($source, "->refresh((string)\$config['ip_risk_blacklist_urls'])");

        $this->assertNotFalse($persistPosition);
        $this->assertNotFalse($refreshPosition);
        $this->assertLessThan($refreshPosition, $persistPosition);
        $this->assertStringContainsString('hasSubscriptionUrlChanges($oldUrlValue, $newUrlValue)', $source);
        $this->assertStringContainsString('catch (\\Throwable $exception)', $source);
        $this->assertStringContainsString('recordUnexpectedFailure($newUrlValue)', $source);
        $this->assertStringContainsString("\$response['refresh_status'] = \$refreshStatus;", $source);
    }

    /**
     * 创建并执行真实的风险配置表单请求校验。
     */
    private function validateRequest(array $payload): ConfigSave
    {
        $request = ConfigSave::create('/config/save', 'POST', $payload);
        $request->setContainer($this->app);
        $request->setRedirector($this->app->make(Redirector::class));
        $request->validateResolved();

        return $request;
    }

    /**
     * 执行表单请求并返回字段校验错误。
     */
    private function validationErrors(array $payload): array
    {
        try {
            $this->validateRequest($payload);
        } catch (ValidationException $exception) {
            return $exception->errors();
        }

        $this->fail('请求应当校验失败');

        return [];
    }

    /**
     * 调用现有控制器读取风险配置分组。
     */
    private function fetchRiskGroup(): array
    {
        $response = (new ConfigController())->fetch(Request::create('/config/fetch', 'GET', ['key' => 'risk']));

        return $response->getOriginalContent();
    }

    /**
     * 返回刷新尚未运行时的稳定显示结构。
     */
    private function notRunStatus(): array
    {
        return [
            'version' => 1,
            'outcome' => 'not_run',
            'started_at' => null,
            'completed_at' => null,
            'source_count' => 0,
            'refreshed_count' => 0,
            'failed_count' => 0,
            'retained_count' => 0,
            'rule_count' => 0,
            'invalid_line_count' => 0,
            'failed_sources' => [],
        ];
    }
}
