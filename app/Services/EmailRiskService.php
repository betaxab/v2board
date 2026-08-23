<?php

namespace App\Services;

use App\Utils\CacheKey;
use Illuminate\Support\Facades\Cache;

class EmailRiskService
{
    private const SNAPSHOT_VERSION = 1;

    public const RESULT_DISABLED = 'disabled';
    public const RESULT_SNAPSHOT_MISSING = 'snapshot_missing';
    public const RESULT_SNAPSHOT_CORRUPT = 'snapshot_corrupt';
    public const RESULT_NOT_MATCHED = 'not_matched';
    public const RESULT_MATCHED = 'matched';

    /**
     * 判断邮箱是否命中当前缓存的风险黑名单。
     */
    public function isBlacklisted(string $email): bool
    {
        return $this->classify($email)['matched'];
    }

    /**
     * 返回不含邮箱或规则内容的缓存分类结果。
     */
    public function classify(string $email): array
    {
        if (!(bool)config('v2board.email_risk_blacklist_enable', 0)) {
            return $this->classificationResult(self::RESULT_DISABLED, false);
        }

        $candidate = $this->normalizeEmail($email);
        if ($candidate === null) {
            return $this->classificationResult(self::RESULT_NOT_MATCHED, false);
        }

        $snapshotKey = CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current');
        if (!Cache::has($snapshotKey)) {
            return $this->classificationResult(self::RESULT_SNAPSHOT_MISSING, false);
        }

        $snapshot = Cache::get($snapshotKey);
        if (!is_array($snapshot)
            || ($snapshot['version'] ?? null) !== self::SNAPSHOT_VERSION
            || !isset($snapshot['rules'])
            || !is_array($snapshot['rules'])) {
            return $this->classificationResult(self::RESULT_SNAPSHOT_CORRUPT, false);
        }

        $parsed = $this->parseRuleLines($snapshot['rules']);
        if ($parsed['invalid_line_count'] > 0) {
            return $this->classificationResult(self::RESULT_SNAPSHOT_CORRUPT, false);
        }

        $matched = $this->matchesAnyRule($candidate, $parsed['rules']);

        return $this->classificationResult(
            $matched ? self::RESULT_MATCHED : self::RESULT_NOT_MATCHED,
            $matched
        );
    }

    /**
     * 解析邮件黑名单规则并返回有效规则及非法行数量。
     */
    public function parseRuleLines($value): array
    {
        if (is_string($value)) {
            $lines = preg_split('/\r\n|\r|\n/', $value);
            $lines = is_array($lines) ? $lines : [];
        } elseif (is_array($value)) {
            $lines = array_values($value);
        } else {
            return ['rules' => [], 'invalid_line_count' => 0];
        }

        $rules = [];
        $seen = [];
        $invalidLineCount = 0;
        foreach ($lines as $line) {
            if (!is_string($line)) {
                $invalidLineCount++;
                continue;
            }

            $leftTrimmed = ltrim($line);
            if ($leftTrimmed === ''
                || strpos($leftTrimmed, '#') === 0
                || strpos($leftTrimmed, ';') === 0
                || strpos($leftTrimmed, '//') === 0) {
                continue;
            }

            $line = trim($line);
            $rule = $this->normalizeRule($line);
            if ($rule === null) {
                $invalidLineCount++;
                continue;
            }

            if (!isset($seen[$rule])) {
                $seen[$rule] = true;
                $rules[] = $rule;
            }
        }

        return ['rules' => $rules, 'invalid_line_count' => $invalidLineCount];
    }

    /**
     * 清理当前邮件黑名单快照。
     */
    public function clearSnapshot(): void
    {
        Cache::forget(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'));
    }

    /**
     * 规范并校验候选邮箱。
     */
    private function normalizeEmail(string $email): ?array
    {
        $normalized = strtolower(trim($email));
        if (substr_count($normalized, '@') !== 1) {
            return null;
        }

        [$localPart, $domain] = explode('@', $normalized, 2);
        if ($localPart === '' || $domain === '') {
            return null;
        }

        return [
            'email' => $normalized,
            'local_part' => $localPart,
        ];
    }

    /**
     * 将单条规则规范为稳定格式。
     */
    private function normalizeRule(string $line): ?string
    {
        if (substr_count($line, ',') !== 1) {
            return null;
        }

        [$type, $value] = explode(',', $line, 2);
        $type = strtoupper(trim($type));
        $value = strtolower(trim($value));
        if ($type === '' || $value === '') {
            return null;
        }

        if ($type === 'NAME-PREFIX') {
            return strpos($value, '@') === false ? $type . ',' . $value : null;
        }

        if ($type === 'NAME-KEYWORD') {
            return $type . ',' . $value;
        }

        if ($type === 'NAME') {
            return $this->normalizeEmail($value) !== null ? $type . ',' . $value : null;
        }

        return null;
    }

    /**
     * 判断候选邮箱是否命中任一有效规则。
     */
    private function matchesAnyRule(array $candidate, array $rules): bool
    {
        foreach ($rules as $rule) {
            [$type, $value] = explode(',', $rule, 2);
            if ($type === 'NAME-PREFIX' && strpos($candidate['local_part'], $value) === 0) {
                return true;
            }

            if ($type === 'NAME-KEYWORD' && strpos($candidate['email'], $value) !== false) {
                return true;
            }

            if ($type === 'NAME' && $candidate['email'] === $value) {
                return true;
            }
        }

        return false;
    }

    /**
     * 构造仅包含稳定状态和命中标记的分类结果。
     */
    private function classificationResult(string $status, bool $matched): array
    {
        return [
            'status' => $status,
            'matched' => $matched,
        ];
    }
}
