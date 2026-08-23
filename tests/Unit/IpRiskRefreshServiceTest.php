<?php

namespace Tests\Unit;

use App\Services\IpRiskRefreshService;
use App\Services\IpRiskService;
use App\Utils\CacheKey;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class IpRiskRefreshServiceTest extends TestCase
{
    /**
     * 重置订阅配置、缓存和 HTTP 假响应。
     */
    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        config([
            'cache.default' => 'array',
            'v2board.ip_risk_blacklist_urls' => '',
            'v2board.ip_risk_blacklist_enable' => 1,
            'v2board.ip_risk_exception_rules' => '',
        ]);
    }

    /**
     * 验证单个订阅会写入单源快照和现有合并快照。
     */
    public function testOneSourceRefreshPublishesCanonicalCombinedSnapshot(): void
    {
        $url = 'https://example.test/blacklist.txt';
        Http::fake([$url => Http::response("203.0.113.7\n2001:0db8::/32\n", 200)]);

        $status = (new IpRiskRefreshService())->refresh($url);
        $sourceHash = hash('sha256', $url);
        $source = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCE', $sourceHash));
        $combined = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'));

        $this->assertSame('success', $status['outcome']);
        $this->assertSame(1, $source['version']);
        $this->assertSame(['203.0.113.7', '2001:db8::/32'], $source['rules']);
        $this->assertIsInt($source['updated_at']);
        $this->assertSame(1, $combined['version']);
        $this->assertSame(['203.0.113.7', '2001:db8::/32'], $combined['rules']);
        $this->assertIsInt($combined['updated_at']);
    }

    /**
     * 验证刷新期间其它写入者无法取得同一把服务锁。
     */
    public function testRefreshHoldsSharedLockDuringNetworkAndCacheWork(): void
    {
        $url = 'https://example.test/locked.txt';
        $lockWasHeld = false;
        Http::fake(function () use (&$lockWasHeld) {
            $lock = Cache::lock(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_LOCK', 'current'), 1);
            $acquired = $lock->get();
            $lockWasHeld = !$acquired;
            if ($acquired) {
                $lock->release();
            }

            return Http::response("198.51.100.1\n", 200);
        });

        (new IpRiskRefreshService())->refresh($url);

        $this->assertTrue($lockWasHeld);
    }

    /**
     * 验证分类器只读取刷新后的合并快照而不会再次发起请求。
     */
    public function testClassifierConsumesCombinedSnapshotWithoutNetworkAccess(): void
    {
        $url = 'https://example.test/classifier.txt';
        Http::fake([$url => Http::response("198.51.100.0/24\n", 200)]);

        (new IpRiskRefreshService())->refresh($url);
        Http::assertSentCount(1);

        $this->assertTrue((new \App\Services\IpRiskService())->isBlacklisted('198.51.100.20'));
        Http::assertSentCount(1);
    }

    /**
     * 验证空白或仅整行注释的响应会被接受为空快照。
     *
     * @dataProvider cleanEmptyBodyProvider
     */
    public function testCleanEmptyResponsesAreAccepted(string $body): void
    {
        $url = 'https://example.test/empty.txt';
        Http::fake([$url => Http::response($body, 200)]);

        $status = (new IpRiskRefreshService())->refresh($url);
        $snapshot = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCE', hash('sha256', $url)));

        $this->assertSame('success', $status['outcome']);
        $this->assertSame([], $snapshot['rules']);
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
     * 验证混合内容保留有效规则并统计非法行。
     */
    public function testMixedContentKeepsValidRulesAndCountsInvalidLines(): void
    {
        $url = 'https://example.test/mixed.txt';
        Http::fake([$url => Http::response(
            "203.0.113.9 # inline comments are invalid\ninvalid\n192.0.2.7/24\n2001:0db8::1\n",
            200
        )]);

        $status = (new IpRiskRefreshService())->refresh($url);
        $snapshot = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCE', hash('sha256', $url)));

        $this->assertSame('success', $status['outcome']);
        $this->assertSame(2, $status['invalid_line_count']);
        $this->assertSame(['192.0.2.0/24', '2001:db8::1'], $snapshot['rules']);
    }

    /**
     * 验证全非法响应不会覆盖该来源最后可用的快照。
     */
    public function testAllInvalidContentRetainsLastUsableSourceSnapshot(): void
    {
        $url = 'https://example.test/retained.txt';
        Http::fake([$url => Http::sequence()
            ->push("203.0.113.0/24\n", 200)
            ->push("invalid\nstill-invalid\n", 200)]);
        $service = new IpRiskRefreshService();
        $service->refresh($url);

        $status = $service->refresh($url);
        $snapshot = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCE', hash('sha256', $url)));

        $this->assertSame('total_failure', $status['outcome']);
        $this->assertSame(1, $status['retained_count']);
        $this->assertSame('invalid_content', $status['failed_sources'][0]['error']);
        $this->assertSame(['203.0.113.0/24'], $snapshot['rules']);
    }

    /**
     * 验证规范重复项会去重但相邻或重叠网段不会合并。
     */
    public function testCanonicalRulesDeduplicateWithoutMergingNetworks(): void
    {
        $url = 'https://example.test/networks.txt';
        Http::fake([$url => Http::response(
            "192.0.2.7/25\n192.0.2.0/25\n192.0.2.128/25\n192.0.2.0/24\n",
            200
        )]);

        (new IpRiskRefreshService())->refresh($url);
        $snapshot = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCE', hash('sha256', $url)));

        $this->assertSame([
            '192.0.2.0/25',
            '192.0.2.128/25',
            '192.0.2.0/24',
        ], $snapshot['rules']);
    }

    /**
     * 验证三个相对或绝对 HTTP 重定向可以成功到达内容。
     */
    public function testFollowsAtMostThreeValidatedHttpRedirects(): void
    {
        Http::fake([
            'https://example.test/start' => Http::response('', 302, ['Location' => '/one']),
            'https://example.test/one' => Http::response('', 301, ['Location' => 'https://internal.test/two']),
            'https://internal.test/two' => Http::response('', 307, ['Location' => '/final']),
            'https://internal.test/final' => Http::response("203.0.113.7\n", 200),
        ]);

        $status = (new IpRiskRefreshService())->refresh('https://example.test/start');

        $this->assertSame('success', $status['outcome']);
        Http::assertSentInOrder([
            'https://example.test/start',
            'https://example.test/one',
            'https://internal.test/two',
            'https://internal.test/final',
        ]);
    }

    /**
     * 验证第四个重定向以及非 HTTP 目标都会被拒绝且不重试。
     */
    public function testRejectsExcessiveAndNonHttpRedirectsWithoutRetry(): void
    {
        Http::fake([
            'https://example.test/start' => Http::response('', 302, ['Location' => '/one']),
            'https://example.test/one' => Http::response('', 302, ['Location' => '/two']),
            'https://example.test/two' => Http::response('', 302, ['Location' => '/three']),
            'https://example.test/three' => Http::response('', 302, ['Location' => '/four']),
        ]);

        $status = (new IpRiskRefreshService())->refresh('https://example.test/start');

        $this->assertSame('total_failure', $status['outcome']);
        $this->assertSame('redirect', $status['failed_sources'][0]['error']);
        Http::assertSentCount(4);

        Http::fake([
            'https://example.test/unsafe' => Http::response('', 302, ['Location' => 'file:///etc/passwd']),
        ]);
        $unsafeStatus = (new IpRiskRefreshService())->refresh('https://example.test/unsafe');
        $this->assertSame('redirect', $unsafeStatus['failed_sources'][0]['error']);
        Http::assertSentCount(1);
    }

    /**
     * 验证连接、超时和服务端错误各自只重试一次。
     *
     * @dataProvider transientFailureProvider
     */
    public function testTransientFailuresRetryExactlyOnce(string $failure): void
    {
        $url = 'https://example.test/retry-' . $failure;
        $calls = 0;
        Http::fake(function () use (&$calls, $failure) {
            $calls++;
            if ($calls === 1) {
                if ($failure === 'http_5xx') {
                    return Http::response('', 503);
                }

                throw new ConnectionException($failure === 'timeout' ? 'Operation timed out' : 'Connection refused');
            }

            return Http::response("203.0.113.7\n", 200);
        });

        $status = (new IpRiskRefreshService())->refresh($url);

        $this->assertSame('success', $status['outcome']);
        $this->assertSame(2, $calls);
    }

    /**
     * 提供允许重试的固定失败类别。
     */
    public function transientFailureProvider(): array
    {
        return [
            'connection' => ['connection'],
            'timeout' => ['timeout'],
            'server error' => ['http_5xx'],
        ];
    }

    /**
     * 验证客户端错误、超限和解析失败不会进入第二次尝试。
     *
     * @dataProvider permanentFailureProvider
     */
    public function testPermanentFailuresAreNotRetried(string $expectedError, string $body, int $statusCode): void
    {
        Http::fake(['*' => Http::response($body, $statusCode)]);

        $status = (new IpRiskRefreshService())->refresh('https://example.test/' . $expectedError);

        $this->assertSame($expectedError, $status['failed_sources'][0]['error']);
        Http::assertSentCount(1);
    }

    /**
     * 提供不可重试的固定失败响应。
     */
    public function permanentFailureProvider(): array
    {
        return [
            'client error' => ['http_4xx', '', 404],
            'oversized response' => ['response_too_large', str_repeat('x', 10485761), 200],
            'invalid content' => ['invalid_content', "invalid\n", 200],
        ];
    }

    /**
     * 验证响应头超限异常被传输层包装后仍保持固定类别且不重试。
     */
    public function testWrappedOversizedHeaderFailureIsNotRetried(): void
    {
        $url = 'https://example.test/oversized-header';
        $calls = 0;
        Http::fake(function () use ($url, &$calls) {
            $calls++;
            throw new RequestException(
                'An error was encountered during the on_headers event',
                new Request('GET', $url),
                null,
                new \RuntimeException('response_too_large')
            );
        });

        $status = (new IpRiskRefreshService())->refresh($url);

        $this->assertSame('response_too_large', $status['failed_sources'][0]['error']);
        $this->assertSame(1, $calls);
    }

    /**
     * 验证每种固定失败类别都不会覆盖最后可用的来源快照。
     *
     * @dataProvider retainedFailureProvider
     */
    public function testEveryFailureCategoryRetainsLastUsableSnapshot(string $failure): void
    {
        $url = 'https://example.test/retain-' . $failure;
        $calls = 0;
        Http::fake(function () use (&$calls, $failure) {
            $calls++;
            if ($calls === 1) {
                return Http::response("192.0.2.0/24\n", 200);
            }

            if ($failure === 'connection') {
                throw new ConnectionException('Connection refused');
            }
            if ($failure === 'timeout') {
                throw new ConnectionException('Operation timed out');
            }
            if ($failure === 'http_5xx') {
                return Http::response('', 503);
            }
            if ($failure === 'http_4xx') {
                return Http::response('', 404);
            }
            if ($failure === 'response_too_large') {
                return Http::response(str_repeat('x', 10485761), 200);
            }
            if ($failure === 'redirect') {
                return Http::response('', 302, ['Location' => 'file:///etc/passwd']);
            }

            return Http::response("invalid\n", 200);
        });
        $service = new IpRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($url);

        $status = $service->refresh($url);
        $snapshot = Cache::get(CacheKey::get(
            'IP_RISK_BLACKLIST_SOURCE',
            hash('sha256', $url)
        ));

        $this->assertSame('total_failure', $status['outcome']);
        $this->assertSame($failure, $status['failed_sources'][0]['error']);
        $this->assertSame(1, $status['retained_count']);
        $this->assertSame(['192.0.2.0/24'], $snapshot['rules']);
    }

    /**
     * 提供必须保留旧快照的全部固定失败类别。
     */
    public function retainedFailureProvider(): array
    {
        return [
            'connection' => ['connection'],
            'timeout' => ['timeout'],
            'server error' => ['http_5xx'],
            'client error' => ['http_4xx'],
            'oversized response' => ['response_too_large'],
            'invalid content' => ['invalid_content'],
            'invalid redirect' => ['redirect'],
        ];
    }

    /**
     * 验证重试和重定向共享同一单源总截止时间。
     */
    public function testAllAttemptsShareOneFifteenSecondDeadline(): void
    {
        $time = 0.0;
        $calls = 0;
        $clock = function () use (&$time): float {
            return $time;
        };
        Http::fake(function () use (&$time, &$calls) {
            $calls++;
            if ($calls === 1) {
                $time = 8.0;
                return Http::response('', 503);
            }

            $time = 16.0;
            return Http::response("203.0.113.7\n", 200);
        });

        $status = (new IpRiskRefreshService(null, $clock))->refresh('https://example.test/deadline');

        $this->assertSame('total_failure', $status['outcome']);
        $this->assertSame('timeout', $status['failed_sources'][0]['error']);
        $this->assertSame(2, $calls);
    }

    /**
     * 验证部分失败会组合成功来源的新快照和失败来源的旧快照。
     */
    public function testPartialFailureCombinesFreshAndRetainedSourceSnapshots(): void
    {
        $firstUrl = 'https://example.test/partial-first.txt';
        $secondUrl = 'https://example.test/partial-second.txt';
        Http::fake([
            $firstUrl => Http::sequence()
                ->push("192.0.2.0/24\n", 200)
                ->push('', 503)
                ->push('', 503),
            $secondUrl => Http::sequence()
                ->push("198.51.100.0/24\n", 200)
                ->push("203.0.113.0/24\n", 200),
        ]);
        $service = new IpRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($firstUrl . "\n" . $secondUrl);

        $status = $service->refresh($firstUrl . "\n" . $secondUrl);
        $combined = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'));

        $this->assertSame('partial_failure', $status['outcome']);
        $this->assertSame(1, $status['refreshed_count']);
        $this->assertSame(1, $status['failed_count']);
        $this->assertSame(1, $status['retained_count']);
        $this->assertSame(['192.0.2.0/24', '203.0.113.0/24'], $combined['rules']);
    }

    /**
     * 验证全部来源失败时仍会发布所有活动来源的保留快照。
     */
    public function testTotalFailurePublishesAllActiveRetainedSnapshots(): void
    {
        $firstUrl = 'https://example.test/total-first.txt';
        $secondUrl = 'https://example.test/total-second.txt';
        Http::fake([
            $firstUrl => Http::sequence()
                ->push("192.0.2.0/24\n", 200)
                ->push('', 503)
                ->push('', 503),
            $secondUrl => Http::sequence()
                ->push("198.51.100.0/24\n", 200)
                ->push('', 503)
                ->push('', 503),
        ]);
        $service = new IpRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($firstUrl . "\n" . $secondUrl);

        $status = $service->refresh($firstUrl . "\n" . $secondUrl);
        $combined = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'));

        $this->assertSame('total_failure', $status['outcome']);
        $this->assertSame(2, $status['failed_count']);
        $this->assertSame(2, $status['retained_count']);
        $this->assertSame(['192.0.2.0/24', '198.51.100.0/24'], $combined['rules']);
    }

    /**
     * 验证没有历史快照的新失败来源不会清除其它来源的保留规则。
     */
    public function testNewFailedSourceContributesNoRulesWithoutErasingRetainedCoverage(): void
    {
        $retainedUrl = 'https://example.test/existing.txt';
        $newUrl = 'https://example.test/new-failure.txt';
        Http::fake([
            $retainedUrl => Http::sequence()
                ->push("192.0.2.0/24\n", 200)
                ->push('', 503)
                ->push('', 503),
            $newUrl => Http::sequence()
                ->push('', 503)
                ->push('', 503),
        ]);
        $service = new IpRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($retainedUrl);

        $status = $service->refresh($retainedUrl . "\n" . $newUrl);
        $combined = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'));

        $this->assertSame('total_failure', $status['outcome']);
        $this->assertSame(1, $status['retained_count']);
        $this->assertSame(['192.0.2.0/24'], $combined['rules']);
        $this->assertNull(Cache::get(CacheKey::get(
            'IP_RISK_BLACKLIST_SOURCE',
            hash('sha256', $newUrl)
        )));
    }

    /**
     * 验证删除来源会在后续网络请求前移除其覆盖和缓存。
     */
    public function testRemovedSourceIsExcludedBeforeRemainingSourceFetch(): void
    {
        $removedUrl = 'https://example.test/removed.txt';
        $activeUrl = 'https://example.test/active.txt';
        $activeCalls = 0;
        $removedHash = hash('sha256', $removedUrl);
        Http::fake(function ($request) use ($removedUrl, $activeUrl, $removedHash, &$activeCalls) {
            if ($request->url() === $removedUrl) {
                return Http::response("192.0.2.0/24\n", 200);
            }

            if ($request->url() === $activeUrl) {
                $activeCalls++;
                if ($activeCalls === 2) {
                    $combined = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'));
                    $this->assertSame(['198.51.100.0/24'], $combined['rules']);
                    $this->assertNull(Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCE', $removedHash)));
                }
                return Http::response("198.51.100.0/24\n", 200);
            }

            return Http::response('', 404);
        });
        $service = new IpRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($removedUrl . "\n" . $activeUrl);

        $status = $service->refresh($activeUrl);

        $this->assertSame('success', $status['outcome']);
        $this->assertSame(2, $activeCalls);
        $this->assertSame([hash('sha256', $activeUrl)], Cache::get(
            CacheKey::get('IP_RISK_BLACKLIST_SOURCES', 'current')
        ));
    }

    /**
     * 验证清空配置会清除活动来源并发布未配置状态和空快照。
     */
    public function testNoConfiguredUrlsPublishesEmptySnapshotAndNotConfiguredStatus(): void
    {
        $url = 'https://example.test/to-be-removed.txt';
        Http::fake([$url => Http::response("192.0.2.0/24\n", 200)]);
        $records = [];
        $service = new IpRiskRefreshService(null, null, function (array $record) use (&$records): void {
            $records[] = $record;
        });
        $service->refresh($url);

        $status = $service->refresh('');
        $combined = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'));

        $this->assertSame('not_configured', $status['outcome']);
        $this->assertSame(0, $status['source_count']);
        $this->assertSame([], $combined['rules']);
        $this->assertSame([], Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCES', 'current')));
        $this->assertNull(Cache::get(CacheKey::get(
            'IP_RISK_BLACKLIST_SOURCE',
            hash('sha256', $url)
        )));
        $this->assertCount(2, $records);
    }

    /**
     * 验证重复和重排 URL 不会改变来源身份集合。
     */
    public function testDuplicateAndReorderedUrlsKeepStableSourceIdentities(): void
    {
        $firstUrl = 'https://example.test/stable-first.txt';
        $secondUrl = 'https://example.test/stable-second.txt';
        Http::fake([
            $firstUrl => Http::response("192.0.2.0/24\n", 200),
            $secondUrl => Http::response("198.51.100.0/24\n", 200),
        ]);
        $service = new IpRiskRefreshService(null, null, function (): void {
        });

        $firstStatus = $service->refresh($firstUrl . "\n" . $firstUrl . "\n" . $secondUrl);
        $firstHashes = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCES', 'current'));
        $secondStatus = $service->refresh($secondUrl . "\n" . $firstUrl);
        $secondHashes = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCES', 'current'));

        $this->assertSame(2, $firstStatus['source_count']);
        $this->assertSame(2, $secondStatus['source_count']);
        $this->assertEqualsCanonicalizing($firstHashes, $secondHashes);
        $this->assertSame([
            hash('sha256', $secondUrl),
            hash('sha256', $firstUrl),
        ], $secondHashes);
    }

    /**
     * 验证最新状态和直接日志只包含固定元数据及脱敏来源。
     */
    public function testLatestStatusAndDirectLogExcludeSecretsAndRequestData(): void
    {
        $url = 'https://user:pass@example.test:8443/path/list.txt?token=secret#fragment';
        Http::fake(['*' => Http::response("private-response\n", 404)]);
        request()->merge(['password' => 'current-request-secret']);
        $records = [];
        $logLockWasHeld = false;
        $service = new IpRiskRefreshService(null, null, function (array $record) use (
            &$records,
            &$logLockWasHeld
        ): void {
            $lock = Cache::lock(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_LOCK', 'current'), 1);
            $acquired = $lock->get();
            $logLockWasHeld = !$acquired;
            if ($acquired) {
                $lock->release();
            }
            $records[] = $record;
        });

        $status = $service->refresh($url);
        $cachedStatus = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current'));

        $this->assertSame($status, $cachedStatus);
        $this->assertSame([
            'version',
            'outcome',
            'started_at',
            'completed_at',
            'source_count',
            'refreshed_count',
            'failed_count',
            'retained_count',
            'rule_count',
            'invalid_line_count',
            'failed_sources',
        ], array_keys($status));
        $this->assertSame('https://example.test:8443/path/list.txt', $status['failed_sources'][0]['source']);
        $this->assertCount(1, $records);
        $this->assertSame('system', $records[0]['host']);
        $this->assertSame('risk:refresh-ip-blacklist', $records[0]['uri']);
        $this->assertSame('SYSTEM', $records[0]['method']);
        $this->assertSame('{}', $records[0]['data']);
        $this->assertNull($records[0]['ip']);
        $this->assertTrue($logLockWasHeld);

        $encoded = json_encode($records[0]);
        $this->assertStringNotContainsString('user', $encoded);
        $this->assertStringNotContainsString('pass', $encoded);
        $this->assertStringNotContainsString('token', $encoded);
        $this->assertStringNotContainsString('fragment', $encoded);
        $this->assertStringNotContainsString('private-response', $encoded);
        $this->assertStringNotContainsString('current-request-secret', $encoded);
    }

    /**
     * 验证锁内未知异常会转为脱敏总失败状态并写入一次日志。
     */
    public function testUnexpectedLockedFailureBecomesSanitizedTotalFailure(): void
    {
        $parser = \Mockery::mock(IpRiskService::class);
        $parser->shouldReceive('parseRuleLines')->once()->andThrow(new \RuntimeException('raw-secret-error'));
        $records = [];
        $service = new IpRiskRefreshService($parser, null, function (array $record) use (&$records): void {
            $records[] = $record;
        });
        Http::fake();

        $status = $service->refresh('https://user:pass@example.test/list?token=secret');

        $this->assertSame('total_failure', $status['outcome']);
        $this->assertSame(1, $status['source_count']);
        $this->assertSame(1, $status['failed_count']);
        $this->assertSame([], $status['failed_sources']);
        $this->assertSame($status, Cache::get(
            CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current')
        ));
        $this->assertCount(1, $records);
        $this->assertStringNotContainsString('raw-secret-error', json_encode($records[0]));
        $this->assertStringNotContainsString('token=secret', json_encode($records[0]));
        Http::assertNothingSent();
    }

    /**
     * 验证锁租约会覆盖全部来源的顺序刷新预算。
     */
    public function testLockLeaseCoversEverySequentialSourceBudget(): void
    {
        $method = new \ReflectionMethod(IpRiskRefreshService::class, 'lockLeaseSeconds');
        $method->setAccessible(true);
        $service = new IpRiskRefreshService(null, null, function (): void {
        });

        $this->assertSame(3600, $method->invoke($service, 1));
        $this->assertSame(3810, $method->invoke($service, 250));
    }

    /**
     * 验证关闭 IP 只清理本域规则缓存并保留诊断状态和邮件缓存。
     */
    public function testDisableClearsOnlyIpRuleCachesAndRetainsLatestStatus(): void
    {
        $url = 'https://example.test/ip-disable.txt';
        $hash = hash('sha256', $url);
        Http::fake([$url => Http::response("203.0.113.7\n", 200)]);
        $service = new IpRiskRefreshService(null, null, function (): void {
        });
        $service->refresh($url);
        $cachedStatus = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current'));
        $emailState = [
            'snapshot' => ['version' => 1, 'rules' => ['NAME,email@example.com']],
            'source' => ['version' => 1, 'rules' => ['NAME,email@example.com']],
            'sources' => ['email-hash'],
            'status' => ['outcome' => 'success'],
            'disabled' => true,
        ];
        Cache::forever(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'), $emailState['snapshot']);
        Cache::forever(CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCE', 'email-hash'), $emailState['source']);
        Cache::forever(CacheKey::get('EMAIL_RISK_BLACKLIST_SOURCES', 'current'), $emailState['sources']);
        Cache::forever(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_STATUS', 'current'), $emailState['status']);
        Cache::forever(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_DISABLED', 'current'), true);
        config(['v2board.ip_risk_blacklist_enable' => 0]);

        $service->disableAndClearSnapshots();
        $latest = $service->getLatestStatus();

        $this->assertNull(Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current')));
        $this->assertNull(Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCE', $hash)));
        $this->assertNull(Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCES', 'current')));
        $this->assertSame($cachedStatus, Cache::get(CacheKey::get(
            'IP_RISK_BLACKLIST_REFRESH_STATUS',
            'current'
        )));
        $this->assertTrue(Cache::get(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_DISABLED', 'current')));
        $this->assertFalse($latest['enabled']);
        $this->assertSame('success', $latest['outcome']);
        $this->assertSame($cachedStatus['completed_at'], $latest['completed_at']);
        $this->assertSame(0, $latest['rule_count']);
        $this->assertSame($emailState['snapshot'], Cache::get(CacheKey::get(
            'EMAIL_RISK_BLACKLIST_SNAPSHOT',
            'current'
        )));
        $this->assertSame($emailState['source'], Cache::get(CacheKey::get(
            'EMAIL_RISK_BLACKLIST_SOURCE',
            'email-hash'
        )));
        $this->assertSame($emailState['sources'], Cache::get(CacheKey::get(
            'EMAIL_RISK_BLACKLIST_SOURCES',
            'current'
        )));
        $this->assertSame($emailState['status'], Cache::get(CacheKey::get(
            'EMAIL_RISK_BLACKLIST_REFRESH_STATUS',
            'current'
        )));
    }

    /**
     * 验证关闭开关或关闭标记会让 IP 定时刷新静默跳过。
     */
    public function testScheduledRefreshSkipsWithoutNetworkStatusOrLogWhenDisabled(): void
    {
        $statusKey = CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current');
        $snapshotKey = CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current');
        $cachedStatus = ['outcome' => 'success', 'completed_at' => 1755691200];
        $cachedSnapshot = ['version' => 1, 'rules' => ['203.0.113.7']];
        Cache::forever($statusKey, $cachedStatus);
        Cache::forever($snapshotKey, $cachedSnapshot);
        config([
            'v2board.ip_risk_blacklist_enable' => 0,
            'v2board.ip_risk_blacklist_urls' => 'https://example.test/disabled.txt',
        ]);
        Http::fake();
        $logs = [];
        $service = new IpRiskRefreshService(null, null, function (array $record) use (&$logs): void {
            $logs[] = $record;
        });

        $this->assertNull($service->refreshScheduled());
        config(['v2board.ip_risk_blacklist_enable' => 1]);
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_DISABLED', 'current'), true);
        $this->assertNull($service->refreshScheduled());

        Http::assertNothingSent();
        $this->assertSame([], $logs);
        $this->assertSame($cachedStatus, Cache::get($statusKey));
        $this->assertSame($cachedSnapshot, Cache::get($snapshotKey));
    }

    /**
     * 验证显式重新启用会在本域锁内移除标记并发布新快照。
     */
    public function testRefreshAfterEnableClearsOnlyIpMarkerAndPublishesFreshSnapshot(): void
    {
        $url = 'https://example.test/ip-enabled.txt';
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_DISABLED', 'current'), true);
        Cache::forever(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_DISABLED', 'current'), true);
        Http::fake([$url => Http::response("198.51.100.9\n", 200)]);

        $status = (new IpRiskRefreshService(null, null, function (): void {
        }))->refreshAfterEnable($url);
        $snapshot = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'));

        $this->assertSame('success', $status['outcome']);
        $this->assertNull(Cache::get(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_DISABLED', 'current')));
        $this->assertTrue(Cache::get(CacheKey::get('EMAIL_RISK_BLACKLIST_REFRESH_DISABLED', 'current')));
        $this->assertSame(['198.51.100.9'], $snapshot['rules']);
        $this->assertTrue((new IpRiskRefreshService())->getLatestStatus()['enabled']);
    }
}
