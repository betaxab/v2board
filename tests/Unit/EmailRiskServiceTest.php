<?php

namespace Tests\Unit;

use App\Services\EmailRiskService;
use App\Utils\CacheKey;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

class EmailRiskServiceTest extends TestCase
{
    /**
     * 重置邮件风控配置和缓存，隔离每个匹配测试。
     */
    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        config(['v2board.email_risk_blacklist_enable' => 1]);
    }

    /**
     * 验证启用邮件风控时缓存中的完整邮箱规则可以命中。
     */
    public function testCachedExactNameMatchesWhenEnabled(): void
    {
        $this->cacheSnapshot(['NAME,test124@gmail.com']);

        $service = new EmailRiskService();

        $this->assertSame([
            'status' => EmailRiskService::RESULT_MATCHED,
            'matched' => true,
        ], $service->classify(' Test124@GMAIL.com '));
        $this->assertTrue($service->isBlacklisted(' Test124@GMAIL.com '));
    }

    /**
     * 验证关闭邮件风控后相同邮箱不会命中。
     */
    public function testDisabledClassifierReturnsFalse(): void
    {
        config(['v2board.email_risk_blacklist_enable' => 0]);
        $this->cacheSnapshot(['NAME,test124@gmail.com']);

        $service = new EmailRiskService();

        $this->assertSame([
            'status' => EmailRiskService::RESULT_DISABLED,
            'matched' => false,
        ], $service->classify('test124@gmail.com'));
        $this->assertFalse($service->isBlacklisted('test124@gmail.com'));
    }

    /**
     * 验证非法候选邮箱在读取异常快照前安全返回。
     */
    public function testMalformedCandidateReturnsFalse(): void
    {
        Cache::put(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'), 'invalid snapshot');

        $service = new EmailRiskService();

        $this->assertSame([
            'status' => EmailRiskService::RESULT_NOT_MATCHED,
            'matched' => false,
        ], $service->classify('not-an-email'));
        $this->assertFalse($service->isBlacklisted('not-an-email'));
    }

    /**
     * 验证不可用邮件快照始终按未命中处理。
     *
     * @dataProvider unusableSnapshotProvider
     */
    public function testUnusableSnapshotReturnsFalse(
        bool $storeSnapshot,
        $snapshot,
        string $expectedStatus
    ): void
    {
        if ($storeSnapshot) {
            Cache::put(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'), $snapshot);
        }

        $service = new EmailRiskService();

        $this->assertSame([
            'status' => $expectedStatus,
            'matched' => false,
        ], $service->classify('test124@gmail.com'));
        $this->assertFalse($service->isBlacklisted('test124@gmail.com'));
    }

    /**
     * 提供缓存缺失和各种错误邮件快照结构。
     */
    public function unusableSnapshotProvider(): array
    {
        return [
            'cache miss' => [false, null, EmailRiskService::RESULT_SNAPSHOT_MISSING],
            'non-array value' => [true, 'invalid snapshot', EmailRiskService::RESULT_SNAPSHOT_CORRUPT],
            'missing version' => [true, ['rules' => ['NAME,test124@gmail.com']], EmailRiskService::RESULT_SNAPSHOT_CORRUPT],
            'wrong version' => [true, ['version' => 2, 'rules' => ['NAME,test124@gmail.com']], EmailRiskService::RESULT_SNAPSHOT_CORRUPT],
            'missing rules' => [true, ['version' => 1], EmailRiskService::RESULT_SNAPSHOT_CORRUPT],
            'non-array rules' => [true, ['version' => 1, 'rules' => 'NAME,test124@gmail.com'], EmailRiskService::RESULT_SNAPSHOT_CORRUPT],
            'empty rules' => [true, ['version' => 1, 'rules' => []], EmailRiskService::RESULT_NOT_MATCHED],
            'no valid rules' => [true, ['version' => 1, 'rules' => ['UNKNOWN,value']], EmailRiskService::RESULT_SNAPSHOT_CORRUPT],
        ];
    }

    /**
     * 验证结构化分类结果不会包含候选邮箱或命中规则。
     */
    public function testClassificationResultContainsOnlyStableFields(): void
    {
        $email = 'sensitive-user@example.com';
        $rule = 'NAME,' . $email;
        $this->cacheSnapshot([$rule]);

        $result = (new EmailRiskService())->classify($email);
        $encoded = (string)json_encode($result);

        $this->assertSame(['status', 'matched'], array_keys($result));
        $this->assertStringNotContainsString($email, $encoded);
        $this->assertStringNotContainsString($rule, $encoded);
    }

    /**
     * 验证清理邮件快照不会删除 IP 风控快照。
     */
    public function testClearSnapshotPreservesIpRiskCache(): void
    {
        $emailKey = CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current');
        $ipKey = CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current');
        Cache::put($emailKey, ['version' => 1, 'rules' => ['NAME,test124@gmail.com']]);
        Cache::put($ipKey, ['version' => 1, 'rules' => ['203.0.113.7']]);

        (new EmailRiskService())->clearSnapshot();

        $this->assertNull(Cache::get($emailKey));
        $this->assertSame(['version' => 1, 'rules' => ['203.0.113.7']], Cache::get($ipKey));
    }

    /**
     * 验证规则解析会忽略全行注释并稳定规范化去重。
     */
    public function testParseRuleLinesNormalizesCommentsAndDuplicates(): void
    {
        $result = (new EmailRiskService())->parseRuleLines(
            "\r\n  # hash\r; semicolon\n\t// slash\r\n"
            . " name-prefix , Test123 \nNAME-KEYWORD, Test125\n"
            . "NAME, Test124@GMAIL.com\nname-prefix,test123"
        );

        $this->assertSame([
            'NAME-PREFIX,test123',
            'NAME-KEYWORD,test125',
            'NAME,test124@gmail.com',
        ], $result['rules']);
        $this->assertSame(0, $result['invalid_line_count']);
    }

    /**
     * 验证非法记录只累计数量且不会泄露原始内容。
     */
    public function testParseRuleLinesCountsOnlyInvalidRecords(): void
    {
        $sensitive = 'secret-user@example.com';
        $result = (new EmailRiskService())->parseRuleLines([
            '',
            ' # comment',
            42,
            'UNKNOWN,value',
            'NAME-PREFIX,' . $sensitive,
            'NAME-PREFIX,',
            'NAME,not-email',
            'NAME,user@example.com,extra',
            ',value',
            'NAME,@example.com',
            'NAME-KEYWORD,ok',
        ]);

        $this->assertSame(['NAME-KEYWORD,ok'], $result['rules']);
        $this->assertSame(8, $result['invalid_line_count']);
        $this->assertStringNotContainsString($sensitive, (string)json_encode($result));
    }

    /**
     * 验证行内注释标记会保留为规则值的一部分。
     */
    public function testInlineCommentMarkersRemainRuleData(): void
    {
        $result = (new EmailRiskService())->parseRuleLines([
            'NAME-KEYWORD,test # note',
            'NAME-PREFIX,prefix ; note',
            'NAME,user@example.com // note',
        ]);

        $this->assertSame([
            'NAME-KEYWORD,test # note',
            'NAME-PREFIX,prefix ; note',
            'NAME,user@example.com // note',
        ], $result['rules']);
        $this->assertSame(0, $result['invalid_line_count']);
    }

    /**
     * 验证三种规则按各自边界匹配候选邮箱。
     *
     * @dataProvider matchingRuleProvider
     */
    public function testRuleMatchesExpectedCandidate(string $rule, string $email, bool $expected): void
    {
        $this->cacheSnapshot([$rule]);

        $this->assertSame($expected, (new EmailRiskService())->isBlacklisted($email));
    }

    /**
     * 提供前缀、关键词、完整邮箱和禁止别名归一化用例。
     */
    public function matchingRuleProvider(): array
    {
        return [
            'prefix local start' => ['NAME-PREFIX,test123', 'test123-user@example.com', true],
            'prefix later local miss' => ['NAME-PREFIX,test123', 'x-test123@example.com', false],
            'prefix domain miss' => ['NAME-PREFIX,test123', 'user@test123.example', false],
            'keyword local hit' => ['NAME-KEYWORD,test125', 'x-test125@example.com', true],
            'keyword domain hit' => ['NAME-KEYWORD,example', 'user@EXAMPLE.com', true],
            'keyword miss' => ['NAME-KEYWORD,test125', 'user@example.com', false],
            'exact normalized hit' => ['NAME, Test124@GMAIL.com ', ' test124@gmail.com ', true],
            'exact suffix miss' => ['NAME,test124@gmail.com', 'test124@gmail.com.cn', false],
            'plus tag preserved' => ['NAME,user@gmail.com', 'user+tag@gmail.com', false],
            'dots preserved' => ['NAME,user.name@gmail.com', 'username@gmail.com', false],
            'unicode exact preserved' => ['NAME,user@bücher.example', 'user@bücher.example', true],
            'IDN not converted' => ['NAME,user@xn--bcher-kva.example', 'user@bücher.example', false],
        ];
    }

    /**
     * 验证结构非法的候选邮箱始终不会命中。
     *
     * @dataProvider malformedEmailProvider
     */
    public function testMalformedEmailNeverMatches(string $email): void
    {
        $this->cacheSnapshot(['NAME-KEYWORD,a']);

        $this->assertFalse((new EmailRiskService())->isBlacklisted($email));
    }

    /**
     * 提供缺失、多余分隔符及空本地段或域名的邮箱。
     */
    public function malformedEmailProvider(): array
    {
        return [
            'no at sign' => ['user.example.com'],
            'multiple at signs' => ['user@@example.com'],
            'empty local part' => ['@example.com'],
            'empty domain' => ['user@'],
            'only at sign' => ['@'],
            'blank' => ['   '],
        ];
    }

    /**
     * 写入当前版本的邮件黑名单快照。
     */
    private function cacheSnapshot(array $rules): void
    {
        Cache::put(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'), [
            'version' => 1,
            'rules' => $rules,
            'updated_at' => 1755691200,
        ]);
    }
}
