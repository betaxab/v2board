<?php

namespace App\Services;

class IpRiskRefreshService extends RiskBlacklistRefreshService
{
    private $ipRiskService;

    /**
     * 注入 IP 规则解析器、可测试时钟和脱敏日志记录器。
     */
    public function __construct(
        ?IpRiskService $ipRiskService = null,
        ?callable $clock = null,
        ?callable $logRecorder = null
    ) {
        $this->ipRiskService = $ipRiskService ?: new IpRiskService();
        parent::__construct($clock, $logRecorder);
    }

    /**
     * 返回持久化的 IP 风险订阅地址。
     */
    protected function configuredUrlValue()
    {
        return config('v2board.ip_risk_blacklist_urls', '');
    }

    /**
     * 返回 IP 风险开关的持久化启用状态。
     */
    protected function enabledConfigValue(): bool
    {
        return (bool)config('v2board.ip_risk_blacklist_enable', 0);
    }

    /**
     * 解析 IP 远程正文并区分干净空列表与全非法内容。
     */
    protected function parseRemoteBody(string $body): array
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
     * 规范化合并后的 IP 和 CIDR 规则。
     */
    protected function normalizeCombinedRules(array $rules): array
    {
        return $this->ipRiskService->parseRuleLines($rules);
    }

    /**
     * 返回 IP 分类器快照缓存族。
     */
    protected function snapshotCacheKey(): string
    {
        return 'IP_RISK_BLACKLIST_SNAPSHOT';
    }

    /**
     * 返回 IP 单源快照缓存族。
     */
    protected function sourceCacheKey(): string
    {
        return 'IP_RISK_BLACKLIST_SOURCE';
    }

    /**
     * 返回 IP 活动来源索引缓存族。
     */
    protected function sourcesCacheKey(): string
    {
        return 'IP_RISK_BLACKLIST_SOURCES';
    }

    /**
     * 返回 IP 最新刷新状态缓存族。
     */
    protected function refreshStatusCacheKey(): string
    {
        return 'IP_RISK_BLACKLIST_REFRESH_STATUS';
    }

    /**
     * 返回 IP 刷新互斥锁缓存族。
     */
    protected function refreshLockCacheKey(): string
    {
        return 'IP_RISK_BLACKLIST_REFRESH_LOCK';
    }

    /**
     * 返回 IP 刷新关闭标记缓存族。
     */
    protected function disabledMarkerCacheKey(): string
    {
        return 'IP_RISK_BLACKLIST_REFRESH_DISABLED';
    }

    /**
     * 返回 IP 刷新的固定日志标题。
     */
    protected function logTitle(): string
    {
        return 'IP 风险黑名单订阅刷新';
    }

    /**
     * 返回 IP 刷新的固定日志 URI。
     */
    protected function logUri(): string
    {
        return 'risk:refresh-ip-blacklist';
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
}
