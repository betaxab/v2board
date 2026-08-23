<?php

namespace Tests\Feature\Admin;

use App\Http\Controllers\V1\Admin\ConfigController;
use App\Http\Requests\Admin\ConfigSave;
use App\Services\EmailRiskRefreshService;
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
            'email_risk_blacklist_enable' => 1,
            'email_risk_blacklist_urls' => "https://mail-one.example/list.txt\nhttp://mail-two.example/rules",
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
            'email_risk_blacklist_enable' => 0,
            'email_risk_blacklist_urls' => null,
        ]);

        $this->assertSame([
            'ip_risk_blacklist_enable' => 0,
            'ip_risk_blacklist_urls' => '',
            'ip_risk_exception_rules' => '',
            'email_risk_blacklist_enable' => 0,
            'email_risk_blacklist_urls' => '',
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
            'v2board.email_risk_blacklist_enable' => '1',
            'v2board.email_risk_blacklist_urls' => "https://mail-one.example/list.txt\nhttps://mail-two.example/list.txt",
        ]);

        $this->assertSame([
            'data' => [
                'risk' => [
                    'ip_risk_blacklist_enable' => 1,
                    'ip_risk_blacklist_urls' => "https://one.example/list.txt\nhttps://two.example/list.txt",
                    'ip_risk_exception_rules' => "192.0.2.7\n2001:db8::/32",
                    'ip_risk_refresh_status' => $this->notRunStatus(true),
                    'email_risk_blacklist_enable' => 1,
                    'email_risk_blacklist_urls' => "https://mail-one.example/list.txt\nhttps://mail-two.example/list.txt",
                    'email_risk_refresh_status' => $this->notRunStatus(true),
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
            $config['ip_risk_exception_rules'],
            $config['email_risk_blacklist_enable'],
            $config['email_risk_blacklist_urls']
        );
        config(['v2board' => $config]);

        $this->assertSame([
            'data' => [
                'risk' => [
                    'ip_risk_blacklist_enable' => 0,
                    'ip_risk_blacklist_urls' => '',
                    'ip_risk_exception_rules' => '',
                    'ip_risk_refresh_status' => $this->notRunStatus(false),
                    'email_risk_blacklist_enable' => 0,
                    'email_risk_blacklist_urls' => '',
                    'email_risk_refresh_status' => $this->notRunStatus(false),
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
            'email_risk_blacklist_enable' => 0,
            'email_risk_blacklist_urls' => null,
        ])->validated();

        foreach ($validated as $key => $value) {
            config(["v2board.{$key}" => $value]);
        }

        $this->assertSame('', $this->fetchRiskGroup()['data']['risk']['ip_risk_blacklist_urls']);
        $this->assertSame('', $this->fetchRiskGroup()['data']['risk']['ip_risk_exception_rules']);
        $this->assertSame('', $this->fetchRiskGroup()['data']['risk']['email_risk_blacklist_urls']);
    }

    /**
     * 验证三个风险键均进入现有保存白名单。
     */
    public function testRiskKeysAreAdmittedByExistingSaveWhitelist(): void
    {
        $this->assertArrayHasKey('ip_risk_blacklist_enable', ConfigSave::RULES);
        $this->assertArrayHasKey('ip_risk_blacklist_urls', ConfigSave::RULES);
        $this->assertArrayHasKey('ip_risk_exception_rules', ConfigSave::RULES);
        $this->assertArrayHasKey('email_risk_blacklist_enable', ConfigSave::RULES);
        $this->assertArrayHasKey('email_risk_blacklist_urls', ConfigSave::RULES);

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
     * 验证邮件订阅地址允许多个 HTTP、HTTPS 地址并保留原始换行。
     */
    public function testEmailSubscriptionUrlsAcceptMultipleHttpSources(): void
    {
        $value = "https://one.example/list.txt\n\n  http://two.example/rules  ";

        $validated = $this->validateRequest([
            'email_risk_blacklist_enable' => 1,
            'email_risk_blacklist_urls' => $value,
        ])->validated();

        $this->assertSame(1, $validated['email_risk_blacklist_enable']);
        $this->assertSame($value, $validated['email_risk_blacklist_urls']);
    }

    /**
     * 验证启用邮件风控时空订阅列表绑定到 URL 字段失败。
     *
     * @dataProvider emptyEnabledEmailUrlsProvider
     */
    public function testEnabledEmailRiskRejectsEmptyUrls(array $payload): void
    {
        $errors = $this->validationErrors($payload + ['email_risk_blacklist_enable' => 1]);

        $this->assertArrayHasKey('email_risk_blacklist_urls', $errors);
    }

    /**
     * 提供缺失、空值和仅空白行的邮件订阅配置。
     */
    public function emptyEnabledEmailUrlsProvider(): array
    {
        return [
            'missing' => [[]],
            'null' => [['email_risk_blacklist_urls' => null]],
            'empty' => [['email_risk_blacklist_urls' => '']],
            'spaces' => [['email_risk_blacklist_urls' => '   ']],
            'blank lines' => [['email_risk_blacklist_urls' => "\n  \n\t"]],
        ];
    }

    /**
     * 验证非法邮件订阅地址返回字段和行号且不回显内容。
     *
     * @dataProvider invalidEmailSubscriptionUrlProvider
     */
    public function testInvalidEmailSubscriptionUrlReturnsSanitizedLineError(string $invalidUrl): void
    {
        $errors = $this->validationErrors([
            'email_risk_blacklist_enable' => 1,
            'email_risk_blacklist_urls' => "https://valid.example/list.txt\n\n{$invalidUrl}",
        ]);

        $this->assertSame('邮件黑名单订阅地址第 3 行格式不正确', $errors['email_risk_blacklist_urls'][0]);
        $this->assertStringNotContainsString($invalidUrl, $errors['email_risk_blacklist_urls'][0]);
    }

    /**
     * 提供禁用协议、缺失主机、凭据和畸形邮件订阅地址。
     */
    public function invalidEmailSubscriptionUrlProvider(): array
    {
        return [
            'FTP scheme' => ['ftp://example.com/list.txt'],
            'relative URL' => ['/private/list.txt'],
            'missing host' => ['http:///list.txt'],
            'credential only' => ['https://user:secret@'],
            'malformed URL' => ['not-a-url'],
        ];
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
     * 验证风险文本配置均拒绝超过固定上限的内容。
     *
     * @dataProvider oversizedTextareaProvider
     */
    public function testRiskTextareasRejectOversizedContent(string $field): void
    {
        $errors = $this->validationErrors([$field => str_repeat('a', 65536)]);

        $this->assertArrayHasKey($field, $errors);
    }

    /**
     * 提供受长度限制的风险文本字段。
     */
    public function oversizedTextareaProvider(): array
    {
        return [
            'subscription URLs' => ['ip_risk_blacklist_urls'],
            'exception rules' => ['ip_risk_exception_rules'],
            'email subscription URLs' => ['email_risk_blacklist_urls'],
        ];
    }

    /**
     * 验证规则构造为风险文本字段安全追加闭包。
     */
    public function testRulesConstructTextareaArraysWithValidationClosures(): void
    {
        $rules = (new ConfigSave())->rules();

        $this->assertIsArray($rules['ip_risk_blacklist_urls']);
        $this->assertIsArray($rules['ip_risk_exception_rules']);
        $this->assertIsArray($rules['email_risk_blacklist_urls']);
        $this->assertCount(4, $rules['ip_risk_blacklist_urls']);
        $this->assertCount(4, $rules['ip_risk_exception_rules']);
        $this->assertCount(5, $rules['email_risk_blacklist_urls']);
        $this->assertInstanceOf(\Closure::class, $rules['ip_risk_blacklist_urls'][3]);
        $this->assertInstanceOf(\Closure::class, $rules['ip_risk_exception_rules'][3]);
        $this->assertInstanceOf(\Closure::class, $rules['email_risk_blacklist_urls'][4]);
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
     * 验证邮件订阅地址使用与 IP 相同的规范化集合比较语义。
     *
     * @dataProvider subscriptionUrlChangeProvider
     */
    public function testEmailSubscriptionUrlChangesCompareNormalizedSets(
        string $before,
        string $after,
        bool $expected
    ): void {
        $service = new EmailRiskRefreshService(null, null, function (): void {
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

        $this->assertSame(
            $this->notRunStatus((bool)config('v2board.ip_risk_blacklist_enable', 0)),
            $service->getLatestStatus()
        );
    }

    /**
     * 验证风险分组读取缓存中的全部刷新结果类型且不发起网络请求。
     *
     * @dataProvider cachedOutcomeProvider
     */
    public function testRiskFetchReturnsTypedCachedRefreshOutcomes(string $outcome): void
    {
        config(['v2board.ip_risk_blacklist_enable' => 1]);
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

        $this->assertSame((bool)config('v2board.ip_risk_blacklist_enable', 0), $status['enabled']);
        $this->assertSame($outcome, $status['outcome']);
        $this->assertSame(100, $status['started_at']);
        $this->assertSame(101, $status['completed_at']);
        $this->assertSame(2, $status['source_count']);
        $this->assertSame(8, $status['rule_count']);
        $this->assertSame('https://example.test:8443/path/list', $status['failed_sources'][0]['source']);
        $this->assertSame('http_5xx', $status['failed_sources'][0]['error']);
    }

    /**
     * 验证邮件刷新状态独立读取且不会改变关闭的 IP 状态。
     */
    public function testRiskFetchReturnsIndependentEmailRefreshStatus(): void
    {
        config([
            'v2board.ip_risk_blacklist_enable' => 0,
            'v2board.email_risk_blacklist_enable' => 1,
        ]);
        Cache::forever(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_STATUS', 'current'), [
            'version' => 1,
            'outcome' => 'partial_failure',
            'started_at' => 100,
            'completed_at' => 101,
            'source_count' => 2,
            'refreshed_count' => 1,
            'failed_count' => 1,
            'retained_count' => 1,
            'rule_count' => 7,
            'invalid_line_count' => 3,
            'failed_sources' => [
                ['source' => 'https://user:pass@example.test/list?token=secret', 'error' => 'http_5xx'],
            ],
        ]);

        $risk = $this->fetchRiskGroup()['data']['risk'];

        $this->assertFalse($risk['ip_risk_refresh_status']['enabled']);
        $this->assertSame(0, $risk['ip_risk_refresh_status']['rule_count']);
        $this->assertTrue($risk['email_risk_refresh_status']['enabled']);
        $this->assertSame('partial_failure', $risk['email_risk_refresh_status']['outcome']);
        $this->assertSame(7, $risk['email_risk_refresh_status']['rule_count']);
        $this->assertSame(
            'https://example.test/list',
            $risk['email_risk_refresh_status']['failed_sources'][0]['source']
        );
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
        $configCachePosition = strpos($source, "Artisan::call('config:cache')");
        $ipDisablePosition = strpos($source, '$this->ipRiskRefreshService->disableAndClearSnapshots();');
        $ipRefreshPosition = strpos($source, '$this->ipRiskRefreshService->refresh($newIpUrlValue)');
        $emailDisablePosition = strpos($source, '$this->emailRiskRefreshService->disableAndClearSnapshots();');
        $emailRefreshPosition = strpos($source, '$this->emailRiskRefreshService->refresh($newEmailUrlValue)');

        $this->assertNotFalse($persistPosition);
        $this->assertNotFalse($configCachePosition);
        $this->assertNotFalse($ipDisablePosition);
        $this->assertNotFalse($ipRefreshPosition);
        $this->assertNotFalse($emailDisablePosition);
        $this->assertNotFalse($emailRefreshPosition);
        $this->assertLessThan($configCachePosition, $persistPosition);
        $this->assertLessThan($ipDisablePosition, $configCachePosition);
        $this->assertLessThan($ipRefreshPosition, $configCachePosition);
        $this->assertLessThan($emailDisablePosition, $configCachePosition);
        $this->assertLessThan($emailRefreshPosition, $configCachePosition);
        $this->assertStringContainsString(
            'hasSubscriptionUrlChanges($oldIpUrlValue, $newIpUrlValue)',
            $source
        );
        $this->assertStringContainsString(
            'hasSubscriptionUrlChanges($oldEmailUrlValue, $newEmailUrlValue)',
            $source
        );
        $this->assertStringContainsString('refreshAfterEnable($newIpUrlValue)', $source);
        $this->assertStringContainsString('refreshAfterEnable($newEmailUrlValue)', $source);
        $this->assertStringContainsString('recordUnexpectedFailure($newIpUrlValue)', $source);
        $this->assertStringContainsString('recordUnexpectedFailure($newEmailUrlValue)', $source);
        $this->assertStringContainsString("\$response['refresh_status'] = \$refreshStatus;", $source);
        $this->assertStringContainsString(
            "\$response['email_refresh_status'] = \$emailRefreshStatus;",
            $source
        );
    }

    /**
     * 验证关闭邮件风控仍保留 URL 且只清理邮件快照。
     */
    public function testDisabledEmailSettingsPreserveUrlsAndClearOnlyEmailSnapshot(): void
    {
        $validated = $this->validateRequest([
            'email_risk_blacklist_enable' => 0,
            'email_risk_blacklist_urls' => "https://one.example/list\nhttps://two.example/list",
        ])->validated();
        $emailKey = CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current');
        $emailSourceKey = CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCE', 'email-source');
        $emailSourcesKey = CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCES', 'current');
        $emailStatusKey = CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_STATUS', 'current');
        $ipKeys = [
            CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'),
            CacheKey::get('IP_RISK_BLACKLIST_SOURCE', 'source-a'),
            CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current'),
        ];
        Cache::put($emailKey, ['version' => 1, 'rules' => ['NAME,user@example.com']]);
        Cache::put($emailSourceKey, ['version' => 1, 'rules' => ['NAME,user@example.com']]);
        Cache::put($emailSourcesKey, ['email-source']);
        Cache::put($emailStatusKey, ['outcome' => 'success']);
        foreach ($ipKeys as $key) {
            Cache::put($key, ['preserved' => $key]);
        }

        config(['v2board.email_risk_blacklist_enable' => 0]);
        (new EmailRiskRefreshService(null, null, function (): void {
        }))->disableAndClearSnapshots();

        $this->assertSame("https://one.example/list\nhttps://two.example/list", $validated['email_risk_blacklist_urls']);
        $this->assertNull(Cache::get($emailKey));
        $this->assertNull(Cache::get($emailSourceKey));
        $this->assertNull(Cache::get($emailSourcesKey));
        $this->assertSame(['outcome' => 'success'], Cache::get($emailStatusKey));
        foreach ($ipKeys as $key) {
            $this->assertSame(['preserved' => $key], Cache::get($key));
        }
    }

    /**
     * 验证邮件配置校验失败时现有快照保持不变。
     */
    public function testInvalidEmailSettingsLeaveSnapshotUntouched(): void
    {
        $key = CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current');
        $snapshot = ['version' => 1, 'rules' => ['NAME,user@example.com']];
        Cache::put($key, $snapshot);

        $this->validationErrors([
            'email_risk_blacklist_enable' => 1,
            'email_risk_blacklist_urls' => 'ftp://secret.example/list',
        ]);

        $this->assertSame($snapshot, Cache::get($key));
    }

    /**
     * 验证两域完整清理严格位于持久化和配置缓存之后。
     */
    public function testEmailSnapshotClearOccursAfterPersistedConfigCache(): void
    {
        $source = file_get_contents(app_path('Http/Controllers/V1/Admin/ConfigController.php'));
        $persistPosition = strpos($source, 'File::put(');
        $configCachePosition = strpos($source, "Artisan::call('config:cache')");
        $ipClearPosition = strpos($source, '$this->ipRiskRefreshService->disableAndClearSnapshots();');
        $emailClearPosition = strpos($source, '$this->emailRiskRefreshService->disableAndClearSnapshots();');

        $this->assertNotFalse($persistPosition);
        $this->assertNotFalse($configCachePosition);
        $this->assertNotFalse($ipClearPosition);
        $this->assertNotFalse($emailClearPosition);
        $this->assertLessThan($configCachePosition, $persistPosition);
        $this->assertLessThan($ipClearPosition, $configCachePosition);
        $this->assertLessThan($emailClearPosition, $configCachePosition);
        $this->assertStringContainsString('$shouldDisableIp = $ipRiskTouched && !$newIpEnabled;', $source);
        $this->assertStringContainsString(
            '$shouldDisableEmail = $emailRiskTouched && !$newEmailEnabled;',
            $source
        );
    }

    /**
     * 验证控制器包含两域独立转换、状态和响应契约。
     */
    public function testPhaseFiveAddsIndependentEmailRefreshPipeline(): void
    {
        $source = file_get_contents(app_path('Http/Controllers/V1/Admin/ConfigController.php'));

        $this->assertStringContainsString('EmailRiskRefreshService', $source);
        $this->assertStringContainsString("'email_risk_refresh_status'", $source);
        $this->assertStringContainsString('$shouldRefreshIp = $ipRiskTouched', $source);
        $this->assertStringContainsString('$shouldRefreshEmail = $emailRiskTouched', $source);
        $this->assertStringContainsString('!$oldIpEnabled || $ipUrlsChanged', $source);
        $this->assertStringContainsString('!$oldEmailEnabled || $emailUrlsChanged', $source);
        $this->assertSame(2, substr_count(
            $source,
            "\$response['email_refresh_status'] = \$emailRefreshStatus;"
        ));
        $this->assertSame(2, substr_count(
            $source,
            "\$response['refresh_status'] = \$refreshStatus;"
        ));
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
    private function notRunStatus(bool $enabled): array
    {
        return [
            'version' => 1,
            'enabled' => $enabled,
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
