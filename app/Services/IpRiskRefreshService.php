<?php

namespace App\Services;

use App\Models\Log as LogModel;
use App\Utils\CacheKey;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\Psr7\UriResolver;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class IpRiskRefreshService
{
    private const SNAPSHOT_VERSION = 1;
    private const SOURCE_BUDGET_SECONDS = 15;
    private const RESPONSE_MAX_BYTES = 10485760;
    private const REDIRECT_MAXIMUM = 3;
    private const ATTEMPT_MAXIMUM = 2;
    private const LOCK_MINIMUM_SECONDS = 3600;
    private const LOCK_WAIT_SECONDS = 3600;
    private const LOCK_GRACE_SECONDS = 60;
    private const ERROR_CATEGORIES = [
        'invalid_url',
        'connection',
        'timeout',
        'redirect',
        'http_status',
        'http_4xx',
        'http_5xx',
        'response_too_large',
        'invalid_content',
        'refresh_failure',
    ];

    private $ipRiskService;
    private $clock;
    private $logRecorder;

    /**
     * 注入规则解析器、可测试时钟和脱敏日志记录器。
     */
    public function __construct(
        ?IpRiskService $ipRiskService = null,
        ?callable $clock = null,
        ?callable $logRecorder = null
    ) {
        $this->ipRiskService = $ipRiskService ?: new IpRiskService();
        $this->clock = $clock ?: function (): float {
            return microtime(true);
        };
        $this->logRecorder = $logRecorder ?: function (array $record): void {
            LogModel::insert($record);
        };
    }

    /**
     * 刷新全部订阅并发布当前合并快照。
     */
    public function refresh(?string $urlList = null): array
    {
        $configuredValue = $urlList === null
            ? config('v2board.ip_risk_blacklist_urls', '')
            : $urlList;
        $urls = $this->normalizeSubscriptionUrls($configuredValue);
        $lock = Cache::lock(
            CacheKey::get('IP_RISK_BLACKLIST_REFRESH_LOCK', 'current'),
            $this->lockLeaseSeconds(count($urls))
        );

        return $lock->block(self::LOCK_WAIT_SECONDS, function () use ($urls): array {
            try {
                return $this->refreshLocked($urls);
            } catch (\Throwable $exception) {
                return $this->recordUnexpectedFailureLocked($urls);
            }
        });
    }

    /**
     * 将多行订阅地址整理为稳定去重的 URL 列表。
     */
    public function normalizeSubscriptionUrls($value): array
    {
        if (is_string($value)) {
            $lines = preg_split('/\r\n|\r|\n/', $value);
            $lines = is_array($lines) ? $lines : [];
        } elseif (is_array($value)) {
            $lines = array_values($value);
        } else {
            return [];
        }

        $urls = [];
        $seen = [];
        foreach ($lines as $line) {
            if (!is_string($line)) {
                continue;
            }

            $url = trim($line);
            if ($url === '' || isset($seen[$url])) {
                continue;
            }

            $seen[$url] = true;
            $urls[] = $url;
        }

        return $urls;
    }

    /**
     * 比较规范化后的订阅 URL 集合是否发生实际变化。
     */
    public function hasSubscriptionUrlChanges($before, $after): bool
    {
        $beforeUrls = $this->normalizeSubscriptionUrls($before);
        $afterUrls = $this->normalizeSubscriptionUrls($after);
        sort($beforeUrls, SORT_STRING);
        sort($afterUrls, SORT_STRING);

        return $beforeUrls !== $afterUrls;
    }

    /**
     * 返回类型稳定且仅含脱敏来源的最新刷新状态。
     */
    public function getLatestStatus(): array
    {
        $cached = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current'));
        $allowedOutcomes = ['not_configured', 'success', 'partial_failure', 'total_failure'];
        if (!is_array($cached) || !in_array($cached['outcome'] ?? null, $allowedOutcomes, true)) {
            return $this->makeNotRunStatus();
        }

        $failedSources = [];
        $cachedSources = isset($cached['failed_sources']) && is_array($cached['failed_sources'])
            ? $cached['failed_sources']
            : [];
        foreach ($cachedSources as $source) {
            if (!is_array($source) || !is_string($source['source'] ?? null)) {
                continue;
            }

            $error = is_string($source['error'] ?? null) ? $source['error'] : 'refresh_failure';
            if (!in_array($error, self::ERROR_CATEGORIES, true)) {
                $error = 'refresh_failure';
            }
            $failedSources[] = [
                'source' => $this->sanitizeUrl($source['source']),
                'error' => $error,
            ];
        }

        return [
            'version' => self::SNAPSHOT_VERSION,
            'outcome' => $cached['outcome'],
            'started_at' => isset($cached['started_at']) ? (int)$cached['started_at'] : null,
            'completed_at' => isset($cached['completed_at']) ? (int)$cached['completed_at'] : null,
            'source_count' => max(0, (int)($cached['source_count'] ?? 0)),
            'refreshed_count' => max(0, (int)($cached['refreshed_count'] ?? 0)),
            'failed_count' => max(0, (int)($cached['failed_count'] ?? 0)),
            'retained_count' => max(0, (int)($cached['retained_count'] ?? 0)),
            'rule_count' => max(0, (int)($cached['rule_count'] ?? 0)),
            'invalid_line_count' => max(0, (int)($cached['invalid_line_count'] ?? 0)),
            'failed_sources' => $failedSources,
        ];
    }

    /**
     * 在配置保存捕获未知异常后记录稳定的失败状态。
     */
    public function recordUnexpectedFailure(string $urlList): array
    {
        $urls = $this->normalizeSubscriptionUrls($urlList);
        $lock = Cache::lock(
            CacheKey::get('IP_RISK_BLACKLIST_REFRESH_LOCK', 'current'),
            $this->lockLeaseSeconds(count($urls))
        );

        try {
            return $lock->block(1, function () use ($urls): array {
                return $this->recordUnexpectedFailureLocked($urls);
            });
        } catch (\Throwable $exception) {
            return $this->makeUnexpectedFailureStatus($urls);
        }
    }

    /**
     * 在共享锁内刷新来源、状态和分类器快照。
     */
    private function refreshLocked(array $urls): array
    {
        $startedAt = (int)$this->now();
        $entries = [];
        foreach ($urls as $url) {
            $entries[] = [
                'url' => $url,
                'hash' => hash('sha256', $url),
            ];
        }

        $activeHashes = array_column($entries, 'hash');
        $previousHashes = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCES', 'current'), []);
        $previousHashes = is_array($previousHashes) ? $previousHashes : [];

        $this->publishCombinedSnapshot($activeHashes, $startedAt);
        foreach (array_diff($previousHashes, $activeHashes) as $removedHash) {
            if (is_string($removedHash)) {
                Cache::forget(CacheKey::get('IP_RISK_BLACKLIST_SOURCE', $removedHash));
            }
        }
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_SOURCES', 'current'), $activeHashes);

        if ($entries === []) {
            $status = $this->makeStatus(
                'not_configured',
                $startedAt,
                0,
                0,
                0,
                0,
                0,
                0,
                []
            );
            Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current'), $status);
            $this->recordStatus($status);
            return $status;
        }

        $refreshedCount = 0;
        $failedCount = 0;
        $retainedCount = 0;
        $invalidLineCount = 0;
        $failedSources = [];

        foreach ($entries as $entry) {
            $result = $this->fetchSource($entry['url']);
            $sourceKey = CacheKey::get('IP_RISK_BLACKLIST_SOURCE', $entry['hash']);
            if ($result['success']) {
                Cache::forever($sourceKey, [
                    'version' => self::SNAPSHOT_VERSION,
                    'rules' => $result['rules'],
                    'updated_at' => (int)$this->now(),
                ]);
                $refreshedCount++;
                $invalidLineCount += $result['invalid_line_count'];
                continue;
            }

            $failedCount++;
            if ($this->readSourceRules($entry['hash']) !== null) {
                $retainedCount++;
            }
            $failedSources[] = [
                'source' => $this->sanitizeUrl($entry['url']),
                'error' => $result['error'],
            ];
        }

        $completedAt = (int)$this->now();
        $rules = $this->publishCombinedSnapshot($activeHashes, $completedAt);
        if ($failedCount === 0) {
            $outcome = 'success';
        } elseif ($refreshedCount > 0) {
            $outcome = 'partial_failure';
        } else {
            $outcome = 'total_failure';
        }

        $status = $this->makeStatus(
            $outcome,
            $startedAt,
            count($entries),
            $refreshedCount,
            $failedCount,
            $retainedCount,
            count($rules),
            $invalidLineCount,
            $failedSources,
            $completedAt
        );
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current'), $status);
        $this->recordStatus($status);

        return $status;
    }

    /**
     * 在锁内持久化不包含异常细节的未知失败状态。
     */
    private function recordUnexpectedFailureLocked(array $urls): array
    {
        $status = $this->makeUnexpectedFailureStatus($urls);
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_REFRESH_STATUS', 'current'), $status);
        $this->recordStatus($status);

        return $status;
    }

    /**
     * 构造不包含原始异常和来源地址的未知失败状态。
     */
    private function makeUnexpectedFailureStatus(array $urls): array
    {
        $timestamp = (int)$this->now();
        $snapshot = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'));
        $ruleCount = is_array($snapshot) && isset($snapshot['rules']) && is_array($snapshot['rules'])
            ? count($snapshot['rules'])
            : 0;

        return $this->makeStatus(
            'total_failure',
            $timestamp,
            count($urls),
            0,
            count($urls),
            0,
            $ruleCount,
            0,
            [],
            $timestamp
        );
    }

    /**
     * 在单源总预算内执行有限重试。
     */
    private function fetchSource(string $url): array
    {
        if (!$this->isHttpUrl($url)) {
            return $this->failedFetch('invalid_url', false);
        }

        $deadline = $this->now() + self::SOURCE_BUDGET_SECONDS;
        for ($attempt = 1; $attempt <= self::ATTEMPT_MAXIMUM; $attempt++) {
            $remaining = $deadline - $this->now();
            if ($remaining <= 0) {
                return $this->failedFetch('timeout', true);
            }

            $attemptsRemaining = self::ATTEMPT_MAXIMUM - $attempt + 1;
            $attemptDeadline = $this->now() + ($remaining / $attemptsRemaining);
            $result = $this->fetchAttempt($url, $attemptDeadline);
            if ($result['success'] || !$result['retryable'] || $attempt === self::ATTEMPT_MAXIMUM) {
                return $result;
            }
        }

        return $this->failedFetch('connection', true);
    }

    /**
     * 在一次尝试中手动跟随受限重定向并解析响应。
     */
    private function fetchAttempt(string $url, float $attemptDeadline): array
    {
        $currentUrl = $url;
        $redirects = 0;

        while (true) {
            $remaining = $attemptDeadline - $this->now();
            if ($remaining <= 0) {
                return $this->failedFetch('timeout', true);
            }

            try {
                $response = Http::timeout(max(0.001, $remaining))
                    ->withOptions([
                        'allow_redirects' => false,
                        'verify' => true,
                        'on_headers' => function ($response): void {
                            $length = $response->getHeaderLine('Content-Length');
                            if ($length !== '' && ctype_digit($length) && (int)$length > self::RESPONSE_MAX_BYTES) {
                                throw new \RuntimeException('response_too_large');
                            }
                        },
                        'progress' => function ($downloadTotal, $downloadedBytes): void {
                            if ($downloadTotal > self::RESPONSE_MAX_BYTES || $downloadedBytes > self::RESPONSE_MAX_BYTES) {
                                throw new \RuntimeException('response_too_large');
                            }
                        },
                    ])
                    ->get($currentUrl);
            } catch (ConnectionException $exception) {
                $message = strtolower($exception->getMessage());
                $category = strpos($message, 'timed out') !== false || strpos($message, 'timeout') !== false
                    ? 'timeout'
                    : 'connection';
                return $this->failedFetch($category, true);
            } catch (\Throwable $exception) {
                $category = $exception->getMessage() === 'response_too_large'
                    ? 'response_too_large'
                    : 'connection';
                return $this->failedFetch($category, $category === 'connection');
            }

            if ($this->now() > $attemptDeadline) {
                return $this->failedFetch('timeout', true);
            }

            $status = $response->status();
            if ($status >= 300 && $status < 400) {
                if ($redirects >= self::REDIRECT_MAXIMUM) {
                    return $this->failedFetch('redirect', false);
                }

                $location = $response->header('Location');
                $redirectUrl = $this->resolveRedirectUrl($currentUrl, $location);
                if ($redirectUrl === null) {
                    return $this->failedFetch('redirect', false);
                }

                $currentUrl = $redirectUrl;
                $redirects++;
                continue;
            }

            if ($status >= 500) {
                return $this->failedFetch('http_5xx', true);
            }
            if ($status >= 400) {
                return $this->failedFetch('http_4xx', false);
            }
            if ($status < 200) {
                return $this->failedFetch('http_status', false);
            }

            $body = $response->body();
            if (strlen($body) > self::RESPONSE_MAX_BYTES) {
                return $this->failedFetch('response_too_large', false);
            }

            return $this->parseRemoteRules($body);
        }
    }

    /**
     * 解析远程规则并区分干净空列表与全非法内容。
     */
    private function parseRemoteRules(string $body): array
    {
        $lines = preg_split('/\r\n|\r|\n/', $body);
        $lines = is_array($lines) ? $lines : [];
        $rules = [];
        $seen = [];
        $invalidLineCount = 0;

        foreach ($lines as $line) {
            $rule = trim($line);
            if ($rule === '' || $this->isCommentLine($rule)) {
                continue;
            }

            $parsed = $this->ipRiskService->parseRuleLines([$rule]);
            if ($parsed === []) {
                $invalidLineCount++;
                continue;
            }

            $normalized = $parsed[0];
            if (!isset($seen[$normalized])) {
                $seen[$normalized] = true;
                $rules[] = $normalized;
            }
        }

        if ($rules === [] && $invalidLineCount > 0) {
            return $this->failedFetch('invalid_content', false);
        }

        return [
            'success' => true,
            'retryable' => false,
            'rules' => $rules,
            'invalid_line_count' => $invalidLineCount,
            'error' => null,
        ];
    }

    /**
     * 判断修剪后的整行是否属于支持的注释格式。
     */
    private function isCommentLine(string $line): bool
    {
        return substr($line, 0, 1) === '#'
            || substr($line, 0, 2) === '//'
            || substr($line, 0, 1) === ';';
    }

    /**
     * 生成不携带远程内容的失败结果。
     */
    private function failedFetch(string $category, bool $retryable): array
    {
        return [
            'success' => false,
            'retryable' => $retryable,
            'rules' => [],
            'invalid_line_count' => 0,
            'error' => $category,
        ];
    }

    /**
     * 解析相对或绝对重定向并限制为 HTTP 协议族。
     */
    private function resolveRedirectUrl(string $baseUrl, $location): ?string
    {
        if (!is_string($location) || trim($location) === '') {
            return null;
        }

        try {
            $resolved = (string)UriResolver::resolve(new Uri($baseUrl), new Uri(trim($location)));
        } catch (\Throwable $exception) {
            return null;
        }

        return $this->isHttpUrl($resolved) ? $resolved : null;
    }

    /**
     * 校验 URL 是否具有 HTTP 协议和非空主机。
     */
    private function isHttpUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        return $scheme === 'http' || $scheme === 'https';
    }

    /**
     * 聚合活动来源并原子发布分类器可见快照。
     */
    private function publishCombinedSnapshot(array $sourceHashes, int $updatedAt): array
    {
        $allRules = [];
        foreach ($sourceHashes as $sourceHash) {
            if (!is_string($sourceHash)) {
                continue;
            }

            $sourceRules = $this->readSourceRules($sourceHash);
            if ($sourceRules !== null) {
                $allRules = array_merge($allRules, $sourceRules);
            }
        }

        $rules = $this->ipRiskService->parseRuleLines($allRules);
        Cache::forever(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'), [
            'version' => self::SNAPSHOT_VERSION,
            'rules' => $rules,
            'updated_at' => $updatedAt,
        ]);

        return $rules;
    }

    /**
     * 读取并校验单源快照中的规则列表。
     */
    private function readSourceRules(string $sourceHash): ?array
    {
        $snapshot = Cache::get(CacheKey::get('IP_RISK_BLACKLIST_SOURCE', $sourceHash));
        if (!is_array($snapshot)
            || ($snapshot['version'] ?? null) !== self::SNAPSHOT_VERSION
            || !isset($snapshot['rules'])
            || !is_array($snapshot['rules'])) {
            return null;
        }

        return $this->ipRiskService->parseRuleLines($snapshot['rules']);
    }

    /**
     * 生成字段稳定的最新刷新状态。
     */
    private function makeStatus(
        string $outcome,
        int $startedAt,
        int $sourceCount,
        int $refreshedCount,
        int $failedCount,
        int $retainedCount,
        int $ruleCount,
        int $invalidLineCount,
        array $failedSources,
        ?int $completedAt = null
    ): array {
        return [
            'version' => self::SNAPSHOT_VERSION,
            'outcome' => $outcome,
            'started_at' => $startedAt,
            'completed_at' => $completedAt === null ? (int)$this->now() : $completedAt,
            'source_count' => $sourceCount,
            'refreshed_count' => $refreshedCount,
            'failed_count' => $failedCount,
            'retained_count' => $retainedCount,
            'rule_count' => $ruleCount,
            'invalid_line_count' => $invalidLineCount,
            'failed_sources' => $failedSources,
        ];
    }

    /**
     * 构造刷新尚未运行时的稳定状态。
     */
    private function makeNotRunStatus(): array
    {
        return [
            'version' => self::SNAPSHOT_VERSION,
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

    /**
     * 重建适合状态和日志展示的脱敏来源地址。
     */
    private function sanitizeUrl(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return 'invalid-url';
        }

        $host = $parts['host'];
        if (strpos($host, ':') !== false && substr($host, 0, 1) !== '[') {
            $host = '[' . $host . ']';
        }

        $display = strtolower($parts['scheme']) . '://' . $host;
        if (isset($parts['port'])) {
            $display .= ':' . $parts['port'];
        }

        $path = isset($parts['path']) && $parts['path'] !== '' ? $parts['path'] : '/';
        return $display . $path;
    }

    /**
     * 直接记录一次固定元数据的脱敏刷新结果。
     */
    private function recordStatus(array $status): void
    {
        $context = json_encode($status, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($context)) {
            $context = '{}';
        }

        $timestamp = isset($status['completed_at']) && is_int($status['completed_at'])
            ? $status['completed_at']
            : (int)$this->now();
        $level = in_array($status['outcome'] ?? null, ['success', 'not_configured'], true)
            ? 'INFO'
            : 'WARNING';

        try {
            call_user_func($this->logRecorder, [
                'title' => 'IP 风险黑名单订阅刷新',
                'level' => $level,
                'host' => 'system',
                'uri' => 'risk:refresh-ip-blacklist',
                'method' => 'SYSTEM',
                'data' => '{}',
                'ip' => null,
                'context' => $context,
                'created_at' => $timestamp,
                'updated_at' => $timestamp,
            ]);
        } catch (\Throwable $exception) {
            // 日志存储失败不能撤销已发布的黑名单快照。
        }
    }

    /**
     * 返回当前单调时间戳。
     */
    private function now(): float
    {
        return (float)call_user_func($this->clock);
    }

    /**
     * 计算覆盖全部顺序来源预算和发布余量的锁租约。
     */
    private function lockLeaseSeconds(int $sourceCount): int
    {
        return max(
            self::LOCK_MINIMUM_SECONDS,
            ($sourceCount * self::SOURCE_BUDGET_SECONDS) + self::LOCK_GRACE_SECONDS
        );
    }
}
