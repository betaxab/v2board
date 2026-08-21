<?php

namespace Tests\Unit;

use App\Models\User;
use App\Services\IpRiskAuthService;
use App\Services\IpRiskService;
use Mockery;
use RuntimeException;
use Tests\TestCase;

class IpRiskAuthServiceTest extends TestCase
{
    /**
     * 验证注册命中时按单调规则更新内存状态且只分类一次。
     *
     * @dataProvider registrationStatusProvider
     */
    public function testPrepareRegistrationAppliesMonotonicStatus(int $current, int $expected): void
    {
        $classifier = Mockery::mock(IpRiskService::class);
        $classifier->shouldReceive('isBlacklisted')->once()->with('203.0.113.10')->andReturnTrue();
        $user = new User();
        $user->verification_status = $current;

        $outcome = (new IpRiskAuthService($classifier, function (): void {
        }))->prepareRegistration($user, '203.0.113.10');

        $this->assertSame($expected, (int)$user->verification_status);
        $this->assertSame([
            'matched' => true,
            'previous_status' => $current,
            'result_status' => $expected,
        ], $outcome);
        $this->assertFalse($user->exists);
    }

    /**
     * 提供注册状态单调升级与深色保留用例。
     */
    public function registrationStatusProvider(): array
    {
        return [
            'grey to red' => [0, 3],
            'orange to red' => [1, 3],
            'green to red' => [2, 3],
            'red unchanged' => [3, 3],
            'dark unchanged' => [4, 4],
        ];
    }

    /**
     * 验证分类异常按未命中处理并写入固定警告事件。
     */
    public function testClassifierFailureFailsOpenWithSanitizedWarning(): void
    {
        $records = [];
        $classifier = Mockery::mock(IpRiskService::class);
        $classifier->shouldReceive('isBlacklisted')->once()->andThrow(new RuntimeException('secret failure'));
        $user = new User();
        $user->id = 9;
        $user->verification_status = 2;
        $service = new IpRiskAuthService($classifier, function (array $record) use (&$records): void {
            $records[] = $record;
        });

        $outcome = $service->prepareRegistration($user, '203.0.113.10');

        $this->assertSame([
            'matched' => false,
            'previous_status' => 2,
            'result_status' => 2,
        ], $outcome);
        $this->assertSame(2, (int)$user->verification_status);
        $this->assertCount(1, $records);
        $this->assertSame('WARNING', $records[0]['level']);
        $this->assertStringNotContainsString('secret failure', json_encode($records[0]));
    }

    /**
     * 验证请求缺少客户端 IP 时按无效地址放行且不产生命中事件。
     */
    public function testMissingClientIpFailsOpenWithoutStatusChange(): void
    {
        $records = [];
        $classifier = Mockery::mock(IpRiskService::class);
        $classifier->shouldReceive('isBlacklisted')->twice()->with('')->andReturnFalse();
        $service = new IpRiskAuthService($classifier, function (array $record) use (&$records): void {
            $records[] = $record;
        });
        $registrationUser = new User();
        $registrationUser->verification_status = 2;
        $loginUser = Mockery::mock(User::class)->makePartial();
        $loginUser->verification_status = 1;
        $loginUser->shouldNotReceive('save');

        $outcome = $service->prepareRegistration($registrationUser, null);
        $service->recordRegistrationMatch($registrationUser, null, $outcome);
        $service->enforceLogin($loginUser, null, IpRiskAuthService::ENTRY_PASSWORD_LOGIN);

        $this->assertSame(2, (int)$registrationUser->verification_status);
        $this->assertSame(1, (int)$loginUser->verification_status);
        $this->assertFalse($outcome['matched']);
        $this->assertSame([], $records);
    }

    /**
     * 验证注册命中仅在显式记录时产生固定脱敏事件。
     */
    public function testRecordRegistrationMatchWritesFixedAuditShape(): void
    {
        $records = [];
        $classifier = Mockery::mock(IpRiskService::class);
        $service = new IpRiskAuthService($classifier, function (array $record) use (&$records): void {
            $records[] = $record;
        });
        $user = new User();
        $user->id = 7;
        $user->email = 'secret@example.test';
        $user->verification_status = 3;

        $service->recordRegistrationMatch($user, '203.0.113.10', [
            'matched' => true,
            'previous_status' => 0,
            'result_status' => 3,
        ]);

        $this->assertCount(1, $records);
        $this->assertSame('INFO', $records[0]['level']);
        $this->assertSame('risk:authentication-enforcement', $records[0]['uri']);
        $this->assertSame('SYSTEM', $records[0]['method']);
        $this->assertSame('{}', $records[0]['data']);
        $context = json_decode($records[0]['context'], true);
        $this->assertSame('register', $context['entry_point']);
        $this->assertSame(7, $context['user_id']);
        $this->assertSame(0, $context['previous_status']);
        $this->assertSame(3, $context['result_status']);
        $this->assertStringNotContainsString('secret@example.test', json_encode($records[0]));
    }

    /**
     * 验证登录命中时只为必要升级保存一次并始终记录命中。
     *
     * @dataProvider loginStatusProvider
     */
    public function testEnforceLoginAppliesMonotonicStatusWithExpectedSaveCount(
        int $current,
        int $expected,
        int $saveCount
    ): void {
        $records = [];
        $classifier = Mockery::mock(IpRiskService::class);
        $classifier->shouldReceive('isBlacklisted')->once()->with('203.0.113.10')->andReturnTrue();
        $user = Mockery::mock(User::class)->makePartial();
        $user->id = 11;
        $user->verification_status = $current;
        $saveExpectation = $user->shouldReceive('save')->times($saveCount);
        if ($saveCount > 0) {
            $saveExpectation->andReturnTrue();
        }
        $service = new IpRiskAuthService($classifier, function (array $record) use (&$records): void {
            $records[] = $record;
        });

        $service->enforceLogin($user, '203.0.113.10', IpRiskAuthService::ENTRY_PASSWORD_LOGIN);

        $this->assertSame($expected, (int)$user->verification_status);
        $this->assertCount(1, $records);
        $this->assertSame('INFO', $records[0]['level']);
    }

    /**
     * 提供登录状态升级、保留和保存次数用例。
     */
    public function loginStatusProvider(): array
    {
        return [
            'grey to red' => [0, 3, 1],
            'orange to red' => [1, 3, 1],
            'green to red' => [2, 3, 1],
            'red no save' => [3, 3, 0],
            'dark no save' => [4, 4, 0],
        ];
    }

    /**
     * 验证保存返回失败时恢复原状态并继续认证边界。
     */
    public function testFalseSaveRestoresPreviousStatusAndRecordsError(): void
    {
        $this->assertPersistenceFailureRestoresStatus(false);
    }

    /**
     * 验证保存抛出异常时恢复原状态且不泄露异常文本。
     */
    public function testThrowingSaveRestoresPreviousStatusAndRecordsError(): void
    {
        $this->assertPersistenceFailureRestoresStatus(new RuntimeException('database secret'));
    }

    /**
     * 验证日志存储异常不会改变注册或登录结果。
     */
    public function testRecorderFailureDoesNotEscapeAuthentication(): void
    {
        $classifier = Mockery::mock(IpRiskService::class);
        $classifier->shouldReceive('isBlacklisted')->twice()->andReturnTrue();
        $service = new IpRiskAuthService($classifier, function (): void {
            throw new RuntimeException('log unavailable');
        });
        $registrationUser = new User();
        $registrationUser->id = 21;
        $registrationUser->verification_status = 0;
        $loginUser = Mockery::mock(User::class)->makePartial();
        $loginUser->id = 22;
        $loginUser->verification_status = 0;
        $loginUser->shouldReceive('save')->once()->andReturnTrue();

        $outcome = $service->prepareRegistration($registrationUser, '203.0.113.10');
        $service->recordRegistrationMatch($registrationUser, '203.0.113.10', $outcome);
        $service->enforceLogin($loginUser, '203.0.113.10', IpRiskAuthService::ENTRY_TOKEN_LOGIN);

        $this->assertSame(3, (int)$registrationUser->verification_status);
        $this->assertSame(3, (int)$loginUser->verification_status);
    }

    /**
     * 断言一次保存失败会恢复状态并产生固定错误事件。
     *
     * @param bool|\Throwable $saveResult
     */
    private function assertPersistenceFailureRestoresStatus($saveResult): void
    {
        $records = [];
        $classifier = Mockery::mock(IpRiskService::class);
        $classifier->shouldReceive('isBlacklisted')->once()->andReturnTrue();
        $user = Mockery::mock(User::class)->makePartial();
        $user->id = 15;
        $user->verification_status = 2;
        $expectation = $user->shouldReceive('save')->once();
        if ($saveResult instanceof \Throwable) {
            $expectation->andThrow($saveResult);
        } else {
            $expectation->andReturn($saveResult);
        }
        $service = new IpRiskAuthService($classifier, function (array $record) use (&$records): void {
            $records[] = $record;
        });

        $service->enforceLogin($user, '203.0.113.10', IpRiskAuthService::ENTRY_PASSWORD_LOGIN);

        $this->assertSame(2, (int)$user->verification_status);
        $this->assertCount(1, $records);
        $this->assertSame('ERROR', $records[0]['level']);
        $context = json_decode($records[0]['context'], true);
        $this->assertSame('persistence_failure', $context['error_category']);
        $this->assertStringNotContainsString('database secret', json_encode($records[0]));
    }
}
