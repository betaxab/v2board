<?php

namespace Tests\Unit;

use App\Services\IpRiskService;
use App\Utils\CacheKey;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

class IpRiskServiceTest extends TestCase
{
    /**
     * 重置风险配置和缓存，隔离每个分类测试。
     */
    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        config([
            'v2board.ip_risk_blacklist_enable' => 1,
            'v2board.ip_risk_exception_rules' => '',
        ]);
    }

    /**
     * 验证启用规则时缓存中的精确 IP 可以命中。
     */
    public function testCachedExactIpMatchesWhenEnabled(): void
    {
        Cache::put(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'), [
            'version' => 1,
            'rules' => ['203.0.113.7'],
            'updated_at' => 1755691200,
        ]);

        $this->assertTrue((new IpRiskService())->isBlacklisted('203.0.113.7'));
    }

    /**
     * 验证关闭风险规则后相同客户端不会命中。
     */
    public function testDisabledClassifierReturnsFalse(): void
    {
        config(['v2board.ip_risk_blacklist_enable' => 0]);
        Cache::put(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'), [
            'version' => 1,
            'rules' => ['203.0.113.7'],
        ]);

        $this->assertFalse((new IpRiskService())->isBlacklisted('203.0.113.7'));
    }

    /**
     * 验证非法客户端地址在读取异常快照前安全返回。
     */
    public function testInvalidClientIpReturnsFalse(): void
    {
        Cache::put(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'), 'invalid snapshot');

        $this->assertFalse((new IpRiskService())->isBlacklisted('not-an-ip'));
    }

    /**
     * 验证不可用快照始终按未命中处理。
     *
     * @dataProvider unusableSnapshotProvider
     */
    public function testUnusableSnapshotReturnsFalse(bool $storeSnapshot, $snapshot): void
    {
        if ($storeSnapshot) {
            Cache::put(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'), $snapshot);
        }

        $this->assertFalse((new IpRiskService())->isBlacklisted('203.0.113.7'));
    }

    /**
     * 提供缓存缺失和各种错误快照结构。
     */
    public function unusableSnapshotProvider(): array
    {
        return [
            'cache miss' => [false, null],
            'non-array value' => [true, 'invalid snapshot'],
            'wrong version' => [true, ['version' => 2, 'rules' => ['203.0.113.7']]],
            'missing rules' => [true, ['version' => 1]],
            'non-array rules' => [true, ['version' => 1, 'rules' => '203.0.113.7']],
            'empty rules' => [true, ['version' => 1, 'rules' => []]],
            'no valid rules' => [true, ['version' => 1, 'rules' => ['invalid', '203.0.113.0/99']]],
        ];
    }

    /**
     * 验证 IPv4、IPv6 和 CIDR 边界的匹配结果。
     *
     * @dataProvider blacklistRuleProvider
     */
    public function testBlacklistRuleMatchesExpectedClient(string $rule, string $clientIp, bool $expected): void
    {
        $this->cacheSnapshot([$rule]);

        $this->assertSame($expected, (new IpRiskService())->isBlacklisted($clientIp));
    }

    /**
     * 提供精确地址、CIDR 边界和地址族隔离用例。
     */
    public function blacklistRuleProvider(): array
    {
        return [
            'IPv4 exact hit' => ['203.0.113.7', '203.0.113.7', true],
            'IPv4 exact miss' => ['203.0.113.7', '203.0.113.8', false],
            'IPv4 zero prefix first' => ['0.0.0.0/0', '0.0.0.0', true],
            'IPv4 zero prefix last' => ['0.0.0.0/0', '255.255.255.255', true],
            'IPv4 24 first' => ['198.51.100.0/24', '198.51.100.0', true],
            'IPv4 24 last' => ['198.51.100.0/24', '198.51.100.255', true],
            'IPv4 24 outside' => ['198.51.100.0/24', '198.51.101.0', false],
            'IPv4 32 hit' => ['203.0.113.7/32', '203.0.113.7', true],
            'IPv4 32 miss' => ['203.0.113.7/32', '203.0.113.8', false],
            'IPv6 zero prefix first' => ['::/0', '::', true],
            'IPv6 zero prefix last' => ['::/0', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', true],
            'IPv6 64 first' => ['2001:db8:abcd:12::/64', '2001:db8:abcd:12::', true],
            'IPv6 64 last' => ['2001:db8:abcd:12::/64', '2001:db8:abcd:12:ffff:ffff:ffff:ffff', true],
            'IPv6 64 outside' => ['2001:db8:abcd:12::/64', '2001:db8:abcd:13::', false],
            'IPv6 128 hit' => ['2001:db8::7/128', '2001:db8::7', true],
            'IPv6 128 miss' => ['2001:db8::7/128', '2001:db8::8', false],
            'IPv4 rule rejects IPv6' => ['203.0.113.7', '2001:db8::7', false],
            'IPv6 rule rejects IPv4' => ['2001:db8::7', '203.0.113.7', false],
            'IPv4 rule rejects mapped IPv6' => ['192.0.2.1', '::ffff:192.0.2.1', false],
        ];
    }

    /**
     * 验证精确地址和 CIDR 例外均优先于黑名单。
     *
     * @dataProvider exceptionPrecedenceProvider
     */
    public function testExceptionsOverrideBlacklist(string $blacklistRule, string $exceptionRule, string $clientIp): void
    {
        config(['v2board.ip_risk_exception_rules' => $exceptionRule]);
        $this->cacheSnapshot([$blacklistRule]);

        $this->assertFalse((new IpRiskService())->isBlacklisted($clientIp));
    }

    /**
     * 提供精确地址与 CIDR 例外的交叉组合。
     */
    public function exceptionPrecedenceProvider(): array
    {
        return [
            'exact over exact' => ['203.0.113.7', '203.0.113.7', '203.0.113.7'],
            'CIDR over exact' => ['203.0.113.7', '203.0.113.0/24', '203.0.113.7'],
            'exact over CIDR' => ['203.0.113.0/24', '203.0.113.7', '203.0.113.7'],
            'CIDR over CIDR' => ['203.0.113.0/24', '203.0.113.0/28', '203.0.113.7'],
        ];
    }

    /**
     * 验证运行时规则解析会规范化并稳定去重。
     *
     * @dataProvider ruleInputProvider
     */
    public function testParseRuleLinesNormalizesValidRules($input): void
    {
        $this->assertSame([
            '203.0.113.7',
            '198.51.100.0/24',
            '2001:db8::/32',
        ], (new IpRiskService())->parseRuleLines($input));
    }

    /**
     * 验证地址别名和带主机位的网段按规范值稳定去重。
     */
    public function testParseRuleLinesCanonicalizesSemanticDuplicates(): void
    {
        $this->assertSame([
            '192.0.2.0/24',
            '2001:db8::1',
            '2001:db8::/32',
        ], (new IpRiskService())->parseRuleLines([
            '192.0.2.7/24',
            '192.0.2.0/24',
            '2001:0db8:0:0:0:0:0:1',
            '2001:db8::1',
            '2001:db8:1234::/32',
            '2001:db8::/32',
        ]));
    }

    /**
     * 提供文本和数组两种规则输入。
     */
    public function ruleInputProvider(): array
    {
        return [
            'newline text' => [" 203.0.113.7\r\n\r\ninvalid\n198.51.100.0/24\r# comment\n203.0.113.7\n2001:db8::/32"],
            'snapshot array' => [[
                ' 203.0.113.7 ',
                '',
                'invalid',
                '198.51.100.0/24',
                '# comment',
                '203.0.113.7',
                '2001:db8::/32',
            ]],
        ];
    }

    /**
     * 验证严格校验返回首个非法非空配置行。
     *
     * @dataProvider invalidRuleLineProvider
     */
    public function testFindInvalidRuleLineReturnsFirstInvalidEntry($input, array $expected): void
    {
        $this->assertSame($expected, (new IpRiskService())->findInvalidRuleLine($input));
    }

    /**
     * 提供非法 CIDR 和注释配置行。
     */
    public function invalidRuleLineProvider(): array
    {
        return [
            'multiple slashes' => ["\n203.0.113.0/24/1", ['line' => 2, 'value' => '203.0.113.0/24/1']],
            'non-decimal prefix' => ['203.0.113.0/x', ['line' => 1, 'value' => '203.0.113.0/x']],
            'IPv4 prefix overflow' => ['203.0.113.0/33', ['line' => 1, 'value' => '203.0.113.0/33']],
            'IPv6 prefix overflow' => ['2001:db8::/129', ['line' => 1, 'value' => '2001:db8::/129']],
            'comment line' => ["203.0.113.7\r\n# comment", ['line' => 2, 'value' => '# comment']],
            'array line number' => [['203.0.113.7', '', 'invalid'], ['line' => 3, 'value' => 'invalid']],
        ];
    }

    /**
     * 验证全部有效的配置规则不会产生错误定位。
     */
    public function testFindInvalidRuleLineReturnsNullForValidRules(): void
    {
        $this->assertNull((new IpRiskService())->findInvalidRuleLine("203.0.113.7\n2001:db8::/32"));
    }

    /**
     * 写入当前版本的风险规则快照。
     */
    private function cacheSnapshot(array $rules): void
    {
        Cache::put(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'), [
            'version' => 1,
            'rules' => $rules,
            'updated_at' => 1755691200,
        ]);
    }
}
