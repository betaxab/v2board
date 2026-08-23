<?php

namespace Tests\Unit;

use App\Services\EmailRiskRefreshService;
use App\Services\EmailRiskService;
use App\Utils\CacheKey;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class EmailRiskRefreshServiceTest extends TestCase
{
    /**
     * 重置邮件订阅配置、缓存和 HTTP 假响应。
     */
    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        config([
            'cache.default' => 'array',
            'v2board.email_risk_blacklist_urls' => '',
            'v2board.email_risk_blacklist_enable' => 1,
        ]);
    }

    /**
     * 验证单个远程规则通过当前快照进入无网络分类器。
     */
    public function testOneSourceRefreshPublishesClassifierSnapshotWithoutExtraRequest(): void
    {
        $url = 'https://example.test/email-blacklist.txt';
        Http::fake([$url => Http::response("NAME,blocked@example.com\n", 200)]);

        $status = (new EmailRiskRefreshService())->refresh($url);
        $source = Cache::get(CacheKey::get(
            'EMAIL_RISK_BLACKLIST_SOURCE',
            hash('sha256', $url)
        ));
        $combined = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'));

        $this->assertSame('success', $status['outcome']);
        $this->assertSame(1, $source['version']);
        $this->assertSame(['NAME,blocked@example.com'], $source['rules']);
        $this->assertIsInt($source['updated_at']);
        $this->assertSame(1, $combined['version']);
        $this->assertSame(['NAME,blocked@example.com'], $combined['rules']);
        $this->assertIsInt($combined['updated_at']);
        Http::assertSentCount(1);

        $this->assertTrue((new EmailRiskService())->isBlacklisted(' BLOCKED@example.com '));
        Http::assertSentCount(1);
    }

    /**
     * 验证刷新期间其它写入者无法取得邮件刷新锁。
     */
    public function testRefreshHoldsEmailLockDuringNetworkAndCacheWork(): void
    {
        $lockWasHeld = false;
        Http::fake(function () use (&$lockWasHeld) {
            $lock = Cache::lock(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_LOCK', 'current'), 1);
            $acquired = $lock->get();
            $lockWasHeld = !$acquired;
            if ($acquired) {
                $lock->release();
            }

            return Http::response("NAME,locked@example.com\n", 200);
        });

        (new EmailRiskRefreshService())->refresh('https://example.test/locked.txt');

        $this->assertTrue($lockWasHeld);
    }

    /**
     * 验证空白或仅整行注释的响应会替换为空来源快照。
     *
     * @dataProvider cleanEmptyBodyProvider
     */
    public function testCleanEmptyResponsesReplaceSourceWithNoRules(string $body): void
    {
        $url = 'https://example.test/empty.txt';
        Http::fake([$url => Http::response($body, 200)]);

        $status = (new EmailRiskRefreshService())->refresh($url);
        $source = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCE', hash('sha256', $url)));

        $this->assertSame('success', $status['outcome']);
        $this->assertSame([], $source['rules']);
        $this->assertSame(0, $status['invalid_line_count']);
    }

    /**
     * 提供空白和三种受支持的整行注释响应。
     */
    public function cleanEmptyBodyProvider(): array
    {
        return [
            'blank' => [" \r\n\t\n"],
            'hash comment' => ["  # comment\n"],
            'slash comment' => ["// comment\r\n"],
            'semicolon comment' => [" ; comment\r"],
        ];
    }

    /**
     * 验证混合内容只发布规范规则并累计非法行数量。
     */
    public function testMixedContentPublishesValidRulesAndCountsInvalidLines(): void
    {
        $url = 'https://example.test/mixed.txt';
        Http::fake([$url => Http::response(
            "UNKNOWN,private-value\nNAME-PREFIX, Test123 \nNAME,blocked@EXAMPLE.com\nNAME,not-email\n",
            200
        )]);

        $status = (new EmailRiskRefreshService())->refresh($url);
        $source = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCE', hash('sha256', $url)));

        $this->assertSame('success', $status['outcome']);
        $this->assertSame(2, $status['invalid_line_count']);
        $this->assertSame([
            'NAME-PREFIX,test123',
            'NAME,blocked@example.com',
        ], $source['rules']);
    }

    /**
     * 验证全非法邮件内容不会覆盖最后可用的来源快照。
     */
    public function testAllInvalidContentRetainsLastUsableSourceSnapshot(): void
    {
        $url = 'https://example.test/retained.txt';
        Http::fake([$url => Http::sequence()
            ->push("NAME,retained@example.com\n", 200)
            ->push("UNKNOWN,secret\nNAME,not-email\n", 200)]);
        $service = new EmailRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($url);

        $status = $service->refresh($url);
        $source = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCE', hash('sha256', $url)));

        $this->assertSame('total_failure', $status['outcome']);
        $this->assertSame(1, $status['retained_count']);
        $this->assertSame('invalid_content', $status['failed_sources'][0]['error']);
        $this->assertSame(['NAME,retained@example.com'], $source['rules']);
    }

    /**
     * 验证多来源重复规则会形成与来源顺序无关的稳定快照。
     */
    public function testMultipleSourcesPublishSortedDeterministicRulesAndFetchDuplicateUrlOnce(): void
    {
        $firstUrl = 'https://example.test/first.txt';
        $secondUrl = 'https://example.test/second.txt';
        Http::fake([
            $firstUrl => Http::response(
                "NAME,z@example.com\nNAME-PREFIX,alpha\nNAME,z@example.com\n",
                200
            ),
            $secondUrl => Http::response(
                "NAME-KEYWORD,example\nNAME-PREFIX,alpha\nNAME,a@example.com\n",
                200
            ),
        ]);
        $service = new EmailRiskRefreshService(null, null, function (): void {
        });

        $firstStatus = $service->refresh($firstUrl . "\n" . $firstUrl . "\n" . $secondUrl);
        $firstRules = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'))['rules'];
        Http::assertSentCount(2);
        $secondStatus = $service->refresh($secondUrl . "\n" . $firstUrl);
        $secondRules = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'))['rules'];

        $expected = [
            'NAME,a@example.com',
            'NAME,z@example.com',
            'NAME-KEYWORD,example',
            'NAME-PREFIX,alpha',
        ];
        $this->assertSame(2, $firstStatus['source_count']);
        $this->assertSame(2, $secondStatus['source_count']);
        $this->assertSame($expected, $firstRules);
        $this->assertSame($expected, $secondRules);
        Http::assertSentCount(4);
    }

    /**
     * 验证部分失败会组合成功来源的新规则和失败来源的保留规则。
     */
    public function testPartialFailureCombinesFreshAndRetainedSourceRules(): void
    {
        $firstUrl = 'https://example.test/partial-first.txt';
        $secondUrl = 'https://example.test/partial-second.txt';
        Http::fake([
            $firstUrl => Http::sequence()
                ->push("NAME,retained@example.com\n", 200)
                ->push('', 503)
                ->push('', 503),
            $secondUrl => Http::sequence()
                ->push("NAME,old@example.com\n", 200)
                ->push("NAME,fresh@example.com\n", 200),
        ]);
        $service = new EmailRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($firstUrl . "\n" . $secondUrl);

        $status = $service->refresh($firstUrl . "\n" . $secondUrl);
        $rules = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'))['rules'];

        $this->assertSame('partial_failure', $status['outcome']);
        $this->assertSame(1, $status['refreshed_count']);
        $this->assertSame(1, $status['retained_count']);
        $this->assertSame([
            'NAME,fresh@example.com',
            'NAME,retained@example.com',
        ], $rules);
    }

    /**
     * 验证全部失败保留已有来源且首次失败来源不贡献规则。
     */
    public function testTotalFailureRetainsExistingSourcesAndIgnoresFirstFailure(): void
    {
        $retainedUrl = 'https://example.test/existing.txt';
        $newUrl = 'https://example.test/new.txt';
        Http::fake([
            $retainedUrl => Http::sequence()
                ->push("NAME,retained@example.com\n", 200)
                ->push('', 503)
                ->push('', 503),
            $newUrl => Http::sequence()->push('', 503)->push('', 503),
        ]);
        $service = new EmailRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($retainedUrl);

        $status = $service->refresh($retainedUrl . "\n" . $newUrl);
        $rules = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'))['rules'];

        $this->assertSame('total_failure', $status['outcome']);
        $this->assertSame(2, $status['failed_count']);
        $this->assertSame(1, $status['retained_count']);
        $this->assertSame(['NAME,retained@example.com'], $rules);
        $this->assertNull(Cache::get(CacheKey::get(
            'EMAIL_RISK_BLACKLIST_SOURCE',
            hash('sha256', $newUrl)
        )));
    }

    /**
     * 验证删除来源会在剩余来源请求前移除其规则和单源缓存。
     */
    public function testRemovedSourceIsExcludedBeforeRemainingSourceFetch(): void
    {
        $removedUrl = 'https://example.test/removed.txt';
        $activeUrl = 'https://example.test/active.txt';
        $activeCalls = 0;
        $removedHash = hash('sha256', $removedUrl);
        Http::fake(function ($request) use ($removedUrl, $activeUrl, $removedHash, &$activeCalls) {
            if ($request->url() === $removedUrl) {
                return Http::response("NAME,removed@example.com\n", 200);
            }

            if ($request->url() === $activeUrl) {
                $activeCalls++;
                if ($activeCalls === 2) {
                    $rules = Cache::get(CacheKey::get(
                        'EMAIL_RISK_BLACKLIST_SNAPSHOT',
                        'current'
                    ))['rules'];
                    $this->assertSame(['NAME,active@example.com'], $rules);
                    $this->assertNull(Cache::get(CacheKey::get(
                        'EMAIL_RISK_BLACKLIST_SOURCE',
                        $removedHash
                    )));
                }
                return Http::response("NAME,active@example.com\n", 200);
            }

            return Http::response('', 404);
        });
        $service = new EmailRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($removedUrl . "\n" . $activeUrl);

        $status = $service->refresh($activeUrl);

        $this->assertSame('success', $status['outcome']);
        $this->assertSame(2, $activeCalls);
        $this->assertSame([hash('sha256', $activeUrl)], Cache::get(
            CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCES', 'current')
        ));
    }

    /**
     * 验证临时失败只重试一次而永久失败不重试。
     */
    public function testRetryPolicyMatchesSharedRequestBoundary(): void
    {
        $retryUrl = 'https://example.test/retry.txt';
        $invalidUrl = 'https://example.test/invalid.txt';
        $retryCalls = 0;
        $invalidCalls = 0;
        Http::fake(function ($request) use ($retryUrl, &$retryCalls, &$invalidCalls) {
            if ($request->url() !== $retryUrl) {
                $invalidCalls++;
                return Http::response("UNKNOWN,private\n", 200);
            }

            $retryCalls++;
            if ($retryCalls === 1) {
                throw new ConnectionException('Connection refused');
            }

            return Http::response("NAME,retried@example.com\n", 200);
        });

        $status = (new EmailRiskRefreshService())->refresh($retryUrl);
        $this->assertSame('success', $status['outcome']);
        $this->assertSame(2, $retryCalls);

        $invalid = (new EmailRiskRefreshService(null, null, function (): void {
        }))->refresh($invalidUrl);
        $this->assertSame('invalid_content', $invalid['failed_sources'][0]['error']);
        $this->assertSame(1, $invalidCalls);
    }

    /**
     * 验证缺失或损坏的状态缓存按稳定的未运行状态读取。
     */
    public function testMissingAndMalformedLatestStatusReturnsTypedNotRunState(): void
    {
        $service = new EmailRiskRefreshService();
        $missing = $service->getLatestStatus();
        Cache::forever(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_STATUS', 'current'), [
            'outcome' => 'unknown',
            'failed_sources' => 'invalid',
        ]);
        $malformed = $service->getLatestStatus();

        $this->assertSame('not_run', $missing['outcome']);
        $this->assertSame($missing, $malformed);
        $this->assertSame([], $malformed['failed_sources']);
    }

    /**
     * 验证最新状态和固定日志排除远程及当前请求中的秘密。
     */
    public function testLatestStatusAndDirectLogExcludeSecretsAndRequestData(): void
    {
        $url = 'https://user:pass@example.test:8443/path/list.txt?token=secret#fragment';
        Http::fake(['*' => Http::response("private-response\n", 404)]);
        request()->merge(['password' => 'current-request-secret']);
        $records = [];
        $logLockWasHeld = false;
        $service = new EmailRiskRefreshService(null, null, function (array $record) use (
            &$records,
            &$logLockWasHeld
        ): void {
            $lock = Cache::lock(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_LOCK', 'current'), 1);
            $acquired = $lock->get();
            $logLockWasHeld = !$acquired;
            if ($acquired) {
                $lock->release();
            }
            $records[] = $record;
        });

        $status = $service->refresh($url);
        $cached = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_STATUS', 'current'));

        $this->assertSame($status, $cached);
        $this->assertSame('https://example.test:8443/path/list.txt', $status['failed_sources'][0]['source']);
        $this->assertSame('WARNING', $records[0]['level']);
        $this->assertSame('邮件风险黑名单订阅刷新', $records[0]['title']);
        $this->assertSame('risk:refresh-email-blacklist', $records[0]['uri']);
        $this->assertTrue($logLockWasHeld);

        $encoded = json_encode([$status, $records]);
        foreach (['user', 'pass', 'token', 'fragment', 'private-response', 'current-request-secret'] as $secret) {
            $this->assertStringNotContainsString($secret, $encoded);
        }
    }

    /**
     * 验证锁内未知异常会转为不包含原始异常的总失败状态。
     */
    public function testUnexpectedLockedFailureBecomesSanitizedTotalFailure(): void
    {
        $parser = \Mockery::mock(EmailRiskService::class);
        $parser->shouldReceive('parseRuleLines')->once()->andThrow(new \RuntimeException('raw-secret-error'));
        $records = [];
        $service = new EmailRiskRefreshService($parser, null, function (array $record) use (&$records): void {
            $records[] = $record;
        });
        Http::fake();

        $status = $service->refresh('https://user:pass@example.test/list?token=secret');

        $this->assertSame('total_failure', $status['outcome']);
        $this->assertSame([], $status['failed_sources']);
        $this->assertCount(1, $records);
        $this->assertStringNotContainsString('raw-secret-error', json_encode($records));
        $this->assertStringNotContainsString('token=secret', json_encode($records));
        Http::assertNothingSent();
    }

    /**
     * 验证锁租约覆盖全部来源的顺序刷新预算。
     */
    public function testLockLeaseCoversEverySequentialSourceBudget(): void
    {
        $method = new \ReflectionMethod(EmailRiskRefreshService::class, 'lockLeaseSeconds');
        $method->setAccessible(true);
        $service = new EmailRiskRefreshService(null, null, function (): void {
        });

        $this->assertSame(3600, $method->invoke($service, 1));
        $this->assertSame(3810, $method->invoke($service, 250));
    }

    /**
     * 验证关闭邮件风控只清理本域规则缓存并保留诊断状态和 IP 缓存。
     */
    public function testDisableClearsOnlyEmailRuleCachesAndRetainsLatestStatus(): void
    {
        $url = 'https://example.test/email-disable.txt';
        $hash = hash('sha256', $url);
        Http::fake([$url => Http::response("NAME,blocked@example.com\n", 200)]);
        $service = new EmailRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($url);
        $cachedStatus = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_STATUS', 'current'));
        $ipState = [
            'snapshot' => ['version' => 1, 'rules' => ['203.0.113.7']],
            'source' => ['version' => 1, 'rules' => ['203.0.113.7']],
            'sources' => ['ip-hash'],
            'status' => ['outcome' => 'success'],
            'disabled' => true,
        ];
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'), $ipState['snapshot']);
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_SOURCE', 'ip-hash'), $ipState['source']);
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_SOURCES', 'current'), $ipState['sources']);
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current'), $ipState['status']);
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_DISABLED', 'current'), true);
        config(['v2board.email_risk_blacklist_enable' => 0]);

        $service->disableAndClearSnapshots();
        $latest = $service->getLatestStatus();

        $this->assertNull(Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current')));
        $this->assertNull(Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCE', $hash)));
        $this->assertNull(Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCES', 'current')));
        $this->assertSame($cachedStatus, Cache::get(CacheKey::get(
            'EMAIL_RISK_BLACKLIST_REFRESH_STATUS',
            'current'
        )));
        $this->assertTrue(Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_DISABLED', 'current')));
        $this->assertFalse($latest['enabled']);
        $this->assertSame('success', $latest['outcome']);
        $this->assertSame($cachedStatus['completed_at'], $latest['completed_at']);
        $this->assertSame(0, $latest['rule_count']);
        $this->assertSame($ipState['snapshot'], Cache::get(CacheKey::get(
            'IP_RISK_BLACKLIST_SNAPSHOT',
            'current'
        )));
        $this->assertSame($ipState['source'], Cache::get(CacheKey::get(
            'IP_RISK_BLACKLIST_SOURCE',
            'ip-hash'
        )));
        $this->assertSame($ipState['sources'], Cache::get(CacheKey::get(
            'IP_RISK_BLACKLIST_SOURCES',
            'current'
        )));
        $this->assertSame($ipState['status'], Cache::get(CacheKey::get(
            'IP_RISK_BLACKLIST_REFRESH_STATUS',
            'current'
        )));
    }

    /**
     * 验证关闭开关或关闭标记会让邮件定时刷新静默跳过。
     */
    public function testScheduledRefreshSkipsWithoutNetworkStatusOrLogWhenDisabled(): void
    {
        $statusKey = CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_STATUS', 'current');
        $snapshotKey = CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current');
        $cachedStatus = ['outcome' => 'success', 'completed_at' => 1755691200];
        $cachedSnapshot = ['version' => 1, 'rules' => ['NAME,blocked@example.com']];
        Cache::forever($statusKey, $cachedStatus);
        Cache::forever($snapshotKey, $cachedSnapshot);
        config([
            'v2board.email_risk_blacklist_enable' => 0,
            'v2board.email_risk_blacklist_urls' => 'https://example.test/disabled.txt',
        ]);
        Http::fake();
        $logs = [];
        $service = new EmailRiskRefreshService(null, null, function (array $record) use (&$logs): void {
            $logs[] = $record;
        });

        $this->assertNull($service->refreshScheduled());
        config(['v2board.email_risk_blacklist_enable' => 1]);
        Cache::forever(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_DISABLED', 'current'), true);
        $this->assertNull($service->refreshScheduled());

        Http::assertNothingSent();
        $this->assertSame([], $logs);
        $this->assertSame($cachedStatus, Cache::get($statusKey));
        $this->assertSame($cachedSnapshot, Cache::get($snapshotKey));
    }

    /**
     * 验证排队的定时刷新在关闭清理释放锁后不能重新发布快照。
     */
    public function testQueuedScheduledRefreshCannotRepublishAfterDisableMarkerCleanup(): void
    {
        $snapshotKey = CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current');
        $sourceKey = CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCE', 'queued-source');
        $sourcesKey = CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCES', 'current');
        $markerKey = CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_DISABLED', 'current');
        Cache::forever($snapshotKey, ['version' => 1, 'rules' => ['NAME,old@example.com']]);
        Cache::forever($sourceKey, ['version' => 1, 'rules' => ['NAME,old@example.com']]);
        Cache::forever($sourcesKey, ['queued-source']);
        config([
            'v2board.email_risk_blacklist_enable' => 1,
            'v2board.email_risk_blacklist_urls' => 'https://example.test/queued.txt',
        ]);
        $lock = Cache::lock(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_LOCK', 'current'), 3600);
        $this->assertTrue($lock->get());

        Cache::forever($markerKey, true);
        Cache::forget($snapshotKey);
        Cache::forget($sourceKey);
        Cache::forget($sourcesKey);
        $lock->release();
        Http::fake();

        $this->assertNull((new EmailRiskRefreshService())->refreshScheduled());
        Http::assertNothingSent();
        $this->assertNull(Cache::get($snapshotKey));
        $this->assertNull(Cache::get($sourceKey));
        $this->assertNull(Cache::get($sourcesKey));
    }

    /**
     * 验证显式重新启用会在本域锁内移除标记并发布新快照。
     */
    public function testRefreshAfterEnableClearsOnlyEmailMarkerAndPublishesFreshSnapshot(): void
    {
        $url = 'https://example.test/email-enabled.txt';
        Cache::forever(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_DISABLED', 'current'), true);
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_DISABLED', 'current'), true);
        Http::fake([$url => Http::response("NAME,enabled@example.com\n", 200)]);

        $service = new EmailRiskRefreshService(null, null, function (): void {
        });
        $status = $service->refreshAfterEnable($url);
        $snapshot = Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'));
        $latest = $service->getLatestStatus();

        $this->assertSame('success', $status['outcome']);
        $this->assertNull(Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_DISABLED', 'current')));
        $this->assertTrue(Cache::get(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_DISABLED', 'current')));
        $this->assertSame(['NAME,enabled@example.com'], $snapshot['rules']);
        $this->assertTrue($latest['enabled']);
        $this->assertSame(1, $latest['rule_count']);
    }
}
