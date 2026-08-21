<?php

namespace App\Services;

use App\Utils\CacheKey;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\IpUtils;

class IpRiskService
{
    private const SNAPSHOT_VERSION = 1;

    /**
     * 判断客户端 IP 是否命中当前缓存的风险黑名单。
     */
    public function isBlacklisted(string $clientIp): bool
    {
        if (!(bool)config('v2board.ip_risk_blacklist_enable', 0)) {
            return false;
        }

        if (filter_var($clientIp, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $exceptions = $this->parseRuleLines(config('v2board.ip_risk_exception_rules', ''));
        if ($this->matchesAnyRule($clientIp, $exceptions)) {
            return false;
        }

        $cacheKey = CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current');
        $snapshot = Cache::get($cacheKey);
        if (!is_array($snapshot)
            || ($snapshot['version'] ?? null) !== self::SNAPSHOT_VERSION
            || !isset($snapshot['rules'])
            || !is_array($snapshot['rules'])) {
            return false;
        }

        return $this->matchesAnyRule($clientIp, $snapshot['rules']);
    }

    /**
     * 解析文本或快照数组中的有效规则并稳定去重。
     */
    public function parseRuleLines($value): array
    {
        if (is_string($value)) {
            $lines = preg_split('/\r\n|\r|\n/', $value);
            $lines = is_array($lines) ? $lines : [];
        } elseif (is_array($value)) {
            $lines = array_values($value);
        } else {
            return [];
        }

        $rules = [];
        $seen = [];
        foreach ($lines as $line) {
            if (!is_string($line)) {
                continue;
            }

            $rule = trim($line);
            $normalizedRule = $this->normalizeRule($rule);
            if ($rule === '' || $normalizedRule === null || isset($seen[$normalizedRule])) {
                continue;
            }

            $seen[$normalizedRule] = true;
            $rules[] = $normalizedRule;
        }

        return $rules;
    }

    /**
     * 返回配置中首个非法非空规则的原始行号和值。
     */
    public function findInvalidRuleLine($value): ?array
    {
        if (is_string($value)) {
            $lines = preg_split('/\r\n|\r|\n/', $value);
            $lines = is_array($lines) ? $lines : [];
        } elseif (is_array($value)) {
            $lines = array_values($value);
        } else {
            return null;
        }

        foreach ($lines as $index => $line) {
            if (!is_string($line)) {
                return ['line' => $index + 1, 'value' => ''];
            }

            $rule = trim($line);
            if ($rule !== '' && !$this->isValidRule($rule)) {
                return ['line' => $index + 1, 'value' => $rule];
            }
        }

        return null;
    }

    /**
     * 判断客户端 IP 是否命中任一有效规则。
     */
    private function matchesAnyRule(string $clientIp, array $rules): bool
    {
        foreach ($this->parseRuleLines($rules) as $rule) {
            if (IpUtils::checkIp($clientIp, $rule)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 校验精确 IP 或 CIDR 规则的地址族和前缀范围。
     */
    private function isValidRule(string $rule): bool
    {
        return $this->normalizeRule($rule) !== null;
    }

    /**
     * 将精确 IP 或 CIDR 规则转换为规范表示。
     */
    private function normalizeRule(string $rule): ?string
    {
        if (filter_var($rule, FILTER_VALIDATE_IP) !== false) {
            $packed = inet_pton($rule);
            if ($packed === false) {
                return null;
            }

            $normalized = inet_ntop($packed);
            return $normalized === false ? null : $normalized;
        }

        if (substr_count($rule, '/') !== 1) {
            return null;
        }

        [$address, $prefix] = explode('/', $rule, 2);
        if ($prefix === '' || !ctype_digit($prefix)) {
            return null;
        }

        $prefixLength = (int)$prefix;
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $maximumPrefix = 32;
        } elseif (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $maximumPrefix = 128;
        } else {
            return null;
        }

        if ($prefixLength > $maximumPrefix) {
            return null;
        }

        $packed = inet_pton($address);
        if ($packed === false) {
            return null;
        }

        $network = '';
        $length = strlen($packed);
        for ($index = 0; $index < $length; $index++) {
            $remainingBits = $prefixLength - ($index * 8);
            if ($remainingBits >= 8) {
                $network .= $packed[$index];
                continue;
            }

            if ($remainingBits <= 0) {
                $network .= chr(0);
                continue;
            }

            $mask = (0xff << (8 - $remainingBits)) & 0xff;
            $network .= chr(ord($packed[$index]) & $mask);
        }

        $normalized = inet_ntop($network);
        return $normalized === false ? null : $normalized . '/' . $prefixLength;
    }
}
