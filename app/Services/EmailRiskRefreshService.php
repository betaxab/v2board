<?php

namespace App\Services;

class EmailRiskRefreshService extends RiskBlacklistRefreshService
{
    private $emailRiskService;

    /**
     * 注入邮件规则解析器、可测试时钟和脱敏日志记录器。
     */
    public function __construct(
        ?EmailRiskService $emailRiskService = null,
        ?callable $clock = null,
        ?callable $logRecorder = null
    ) {
        $this->emailRiskService = $emailRiskService ?: new EmailRiskService();
        parent::__construct($clock, $logRecorder);
    }

    /**
     * 返回持久化的邮件风险订阅地址。
     */
    protected function configuredUrlValue()
    {
        return config('v2board.email_risk_blacklist_urls', '');
    }

    /**
     * 返回邮件风险开关的持久化启用状态。
     */
    protected function enabledConfigValue(): bool
    {
        return (bool)config('v2board.email_risk_blacklist_enable', 0);
    }

    /**
     * 解析邮件远程正文并拒绝全非法内容。
     */
    protected function parseRemoteBody(string $body): array
    {
        $parsed = $this->emailRiskService->parseRuleLines($body);
        if ($parsed['rules'] === [] && $parsed['invalid_line_count'] > 0) {
            return $this->failedFetch('invalid_content', false);
        }

        return [
            'success' => true,
            'retryable' => false,
            'rules' => $parsed['rules'],
            'invalid_line_count' => $parsed['invalid_line_count'],
            'error' => null,
        ];
    }

    /**
     * 规范化、去重并稳定排序合并后的邮件规则。
     */
    protected function normalizeCombinedRules(array $rules): array
    {
        $parsed = $this->emailRiskService->parseRuleLines($rules);
        $rules = $parsed['rules'];
        sort($rules, SORT_STRING);

        return $rules;
    }

    /**
     * 返回邮件分类器快照缓存族。
     */
    protected function snapshotCacheKey(): string
    {
        return 'EMAIL_RISK_BLACKLIST_SNAPSHOT';
    }

    /**
     * 返回邮件单源快照缓存族。
     */
    protected function sourceCacheKey(): string
    {
        return 'EMAIL_RISK_BLACKLIST_SOURCE';
    }

    /**
     * 返回邮件活动来源索引缓存族。
     */
    protected function sourcesCacheKey(): string
    {
        return 'EMAIL_RISK_BLACKLIST_SOURCES';
    }

    /**
     * 返回邮件最新刷新状态缓存族。
     */
    protected function refreshStatusCacheKey(): string
    {
        return 'EMAIL_RISK_BLACKLIST_REFRESH_STATUS';
    }

    /**
     * 返回邮件刷新互斥锁缓存族。
     */
    protected function refreshLockCacheKey(): string
    {
        return 'EMAIL_RISK_BLACKLIST_REFRESH_LOCK';
    }

    /**
     * 返回邮件刷新关闭标记缓存族。
     */
    protected function disabledMarkerCacheKey(): string
    {
        return 'EMAIL_RISK_BLACKLIST_REFRESH_DISABLED';
    }

    /**
     * 返回邮件刷新的固定日志标题。
     */
    protected function logTitle(): string
    {
        return '邮件风险黑名单订阅刷新';
    }

    /**
     * 返回邮件刷新的固定日志 URI。
     */
    protected function logUri(): string
    {
        return 'risk:refresh-email-blacklist';
    }
}
