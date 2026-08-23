<?php

namespace Tests\Feature\Passport;

use App\Models\InviteCode;
use App\Models\User;
use App\Services\EmailRiskAuthService;
use App\Services\EmailRiskService;
use App\Services\IpRiskAuthService;
use App\Services\IpRiskService;
use App\Utils\CacheKey;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Mockery;
use Tests\TestCase;

class AuthRiskEnforcementTest extends TestCase
{
    private const MATCHED_IP = '203.0.113.10';
    private const PASSWORD = 'phase3-password';

    /**
     * 建立认证路由所需的 SQLite 表和确定性配置。
     */
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'app.key' => str_repeat('phase3-auth-risk-key-', 4),
            'cache.default' => 'array',
            'database.default' => 'sqlite',
            'database.connections.sqlite' => [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
                'foreign_key_constraints' => false,
            ],
            'v2board.recaptcha_enable' => 0,
            'v2board.email_whitelist_enable' => 0,
            'v2board.email_gmail_limit_enable' => 0,
            'v2board.stop_register' => 0,
            'v2board.invite_force' => 0,
            'v2board.invite_never_expire' => 1,
            'v2board.email_verify' => 0,
            'v2board.register_limit_by_ip_enable' => 0,
            'v2board.password_limit_enable' => 0,
            'v2board.try_out_plan_id' => 0,
            'v2board.ip_risk_blacklist_enable' => 1,
            'v2board.ip_risk_exception_rules' => '',
            'v2board.email_risk_blacklist_enable' => 0,
        ]);
        DB::purge('sqlite');
        DB::reconnect('sqlite');
        Cache::flush();
        $this->createTables();
        $this->installSnapshot([self::MATCHED_IP]);
    }

    /**
     * 关闭 SQLite 连接并清理容器绑定。
     */
    protected function tearDown(): void
    {
        DB::disconnect('sqlite');
        Mockery::close();
        parent::tearDown();
    }

    /**
     * 验证命中注册只分类一次并在首次保存时写入红色状态。
     */
    public function testMatchedRegistrationClassifiesOnceAndPersistsRedOnFirstSave(): void
    {
        $classifier = Mockery::mock(IpRiskService::class);
        $classifier->shouldReceive('isBlacklisted')->once()->with(self::MATCHED_IP)->andReturnTrue();
        $this->app->instance(IpRiskService::class, $classifier);

        $response = $this->register('new-user@example.test');

        $response->assertOk();
        $this->assertAuthPayload($response->json('data'));
        $user = User::where('email', 'new-user@example.test')->firstOrFail();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertSame(self::MATCHED_IP, $user->last_login_ip);
        $this->assertNotNull($user->last_login_at);
        $this->assertSessionCreated($user);
        $this->assertMatchedAudit('register', $user, 0, 3);
    }

    /**
     * 验证深色邀请状态优先于注册黑名单命中。
     */
    public function testMatchedRegistrationPreservesDarkInvitationStatus(): void
    {
        $inviter = $this->createUser(['verification_status' => 4]);
        $invite = $this->createInvite($inviter);

        $response = $this->register('dark-invite@example.test', $invite->code);

        $response->assertOk();
        $user = User::where('email', 'dark-invite@example.test')->firstOrFail();
        $this->assertSame(4, (int)$user->verification_status);
        $this->assertMatchedAudit('register', $user, 4, 4);
    }

    /**
     * 验证红色邀请状态在注册黑名单命中时保持红色。
     */
    public function testMatchedRegistrationPreservesRedInvitationStatus(): void
    {
        $inviter = $this->createUser(['verification_status' => 3]);
        $invite = $this->createInvite($inviter);

        $response = $this->register('red-invite@example.test', $invite->code);

        $response->assertOk();
        $user = User::where('email', 'red-invite@example.test')->firstOrFail();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertMatchedAudit('register', $user, 3, 3);
    }

    /**
     * 验证三种缓存邮件规则通过真实注册路由持久化红色状态。
     *
     * @dataProvider emailRegistrationRuleProvider
     */
    public function testEmailRuleRegistrationPersistsRedWithAuthSession(
        string $rule,
        string $email
    ): void {
        config(['v2board.email_risk_blacklist_enable' => 1]);
        $this->installEmailSnapshot([$rule]);

        $response = $this->register($email, null, '198.51.100.10');

        $response->assertOk();
        $this->assertAuthPayload($response->json('data'));
        $user = User::where('email', $email)->firstOrFail();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertSessionCreated($user, '198.51.100.10');
        $this->assertEmailAudit($user, 'matched', 'INFO', 0, 3, null, [$rule]);
    }

    /**
     * 提供前缀、关键词和完整邮箱注册命中用例。
     */
    public function emailRegistrationRuleProvider(): array
    {
        return [
            'prefix' => ['NAME-PREFIX,prefix-risk', 'prefix-risk-user@example.test'],
            'keyword' => ['NAME-KEYWORD,keyword-risk', 'user@keyword-risk.example'],
            'exact' => ['NAME,exact-risk@example.test', 'exact-risk@example.test'],
        ];
    }

    /**
     * 验证邮件命中不会降低深色邀请状态且仍记录邮件事件。
     */
    public function testEmailMatchPreservesDarkInvitationStatus(): void
    {
        config(['v2board.email_risk_blacklist_enable' => 1]);
        $email = 'email-dark-invite@example.test';
        $this->installEmailSnapshot(['NAME,' . $email]);
        $inviter = $this->createUser(['verification_status' => 4]);
        $invite = $this->createInvite($inviter);

        $response = $this->register($email, $invite->code, '198.51.100.10');

        $response->assertOk();
        $user = User::where('email', $email)->firstOrFail();
        $this->assertSame(4, (int)$user->verification_status);
        $this->assertEmailAudit($user, 'matched', 'INFO', 4, 4);
    }

    /**
     * 验证 IP 和邮件同时命中时分别记录独立事件。
     */
    public function testIpAndEmailMatchesCreateIndependentAudits(): void
    {
        config(['v2board.email_risk_blacklist_enable' => 1]);
        $email = 'dual-risk@example.test';
        $this->installEmailSnapshot(['NAME,' . $email]);

        $response = $this->register($email);

        $response->assertOk();
        $user = User::where('email', $email)->firstOrFail();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertSame(1, DB::table('v2_log')->where('uri', 'risk:authentication-enforcement')->count());
        $this->assertSame(1, DB::table('v2_log')->where('uri', 'risk:email-registration-enforcement')->count());
    }

    /**
     * 验证 IP 分类异常不会抑制邮件命中、状态提升和独立事件。
     */
    public function testIpClassifierExceptionCannotSuppressEmailMatch(): void
    {
        config(['v2board.email_risk_blacklist_enable' => 1]);
        $email = 'ip-exception-email-match@example.test';
        $this->installEmailSnapshot(['NAME,' . $email]);
        $classifier = Mockery::mock(IpRiskService::class);
        $classifier->shouldReceive('isBlacklisted')->once()
            ->andThrow(new \RuntimeException('ip-classifier-exception-sentinel'));
        $this->app->instance(IpRiskService::class, $classifier);

        $response = $this->register($email);

        $response->assertOk();
        $user = User::where('email', $email)->firstOrFail();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertSessionCreated($user);
        $this->assertEmailAudit($user, 'matched', 'INFO', 0, 3);
        $this->assertDomainAudit(
            'risk:authentication-enforcement',
            'classifier_failure',
            'WARNING',
            null,
            ['ip-classifier-exception-sentinel']
        );
    }

    /**
     * 验证 IP 主审计失败不会抑制独立邮件命中事件。
     */
    public function testIpAuditFailureCannotSuppressEmailMatch(): void
    {
        config(['v2board.email_risk_blacklist_enable' => 1]);
        $email = 'ip-audit-failure-email-match@example.test';
        $this->installEmailSnapshot(['NAME,' . $email]);
        $classifier = Mockery::mock(IpRiskService::class);
        $classifier->shouldReceive('isBlacklisted')->once()->andReturnTrue();
        $service = new IpRiskAuthService($classifier, function (): void {
            throw new \RuntimeException('ip-audit-exception-sentinel');
        });
        $this->app->instance(IpRiskAuthService::class, $service);

        $response = $this->register($email);

        $response->assertOk();
        $user = User::where('email', $email)->firstOrFail();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertSessionCreated($user);
        $this->assertSame(0, DB::table('v2_log')->where('uri', 'risk:authentication-enforcement')->count());
        $this->assertEmailAudit(
            $user,
            'matched',
            'INFO',
            3,
            3,
            null,
            ['ip-audit-exception-sentinel']
        );
    }

    /**
     * 验证邮件分类异常不会抑制 IP 命中状态和两个独立事件。
     */
    public function testEmailClassifierFailureCannotSuppressIpMatch(): void
    {
        config(['v2board.email_risk_blacklist_enable' => 1]);
        $email = 'email-exception-ip-match@example.test';
        $classifier = Mockery::mock(EmailRiskService::class);
        $classifier->shouldReceive('classify')->once()->with($email)
            ->andThrow(new \RuntimeException('email-classifier-exception-sentinel'));
        $this->app->instance(EmailRiskService::class, $classifier);

        $response = $this->register($email);

        $response->assertOk();
        $user = User::where('email', $email)->firstOrFail();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertSessionCreated($user);
        $this->assertDomainAudit(
            'risk:authentication-enforcement',
            'matched',
            'INFO',
            $user->id
        );
        $this->assertEmailAudit(
            $user,
            'classifier_failure',
            'WARNING',
            3,
            3,
            'classifier_failure',
            ['email-classifier-exception-sentinel']
        );
    }

    /**
     * 验证邮件命中保留红色邀请状态且仍记录命中事件。
     */
    public function testEmailMatchPreservesRedInvitationStatus(): void
    {
        config(['v2board.email_risk_blacklist_enable' => 1]);
        $email = 'email-red-invite@example.test';
        $this->installEmailSnapshot(['NAME,' . $email]);
        $inviter = $this->createUser(['verification_status' => 3]);
        $invite = $this->createInvite($inviter);

        $response = $this->register($email, $invite->code, '198.51.100.10');

        $response->assertOk();
        $user = User::where('email', $email)->firstOrFail();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertSessionCreated($user, '198.51.100.10');
        $this->assertEmailAudit($user, 'matched', 'INFO', 3, 3);
    }

    /**
     * 验证控制器接受成功降级结果并保留邀请基线及正常会话。
     */
    public function testFallbackSavedResultRetainsInvitationBaselineAndIssuesSession(): void
    {
        $email = 'fallback-invite@example.test';
        $inviter = $this->createUser(['verification_status' => 3]);
        $invite = $this->createInvite($inviter);
        $outcome = [
            'classification' => EmailRiskService::RESULT_MATCHED,
            'matched' => true,
            'promoted' => true,
            'previous_status' => 3,
            'result_status' => 3,
        ];
        $persistence = ['status' => EmailRiskAuthService::PERSIST_FALLBACK_SAVED];
        $service = Mockery::mock(EmailRiskAuthService::class);
        $service->shouldReceive('prepareRegistration')->once()->with(
            Mockery::on(function (User $user): bool {
                return (int)$user->verification_status === 3;
            }),
            $email
        )->andReturn($outcome);
        $service->shouldReceive('persistRegistration')->once()->andReturnUsing(
            function (User $user) use ($persistence): array {
                $user->verification_status = 3;
                $this->assertTrue($user->save());

                return $persistence;
            }
        );
        $service->shouldReceive('recordRegistrationOutcome')->once()->with(
            Mockery::on(function (User $user): bool {
                return $user->exists && $user->getKey() !== null
                    && (int)$user->verification_status === 3;
            }),
            $outcome,
            $persistence
        );
        $this->app->instance(EmailRiskAuthService::class, $service);

        $response = $this->register($email, $invite->code, '198.51.100.10');

        $response->assertOk();
        $this->assertAuthPayload($response->json('data'));
        $user = User::where('email', $email)->firstOrFail();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertSessionCreated($user, '198.51.100.10');
    }

    /**
     * 验证持久化最终失败沿用注册失败响应且不签发用户会话。
     */
    public function testFailedEmailPersistenceReturnsRegisterFailureWithoutSession(): void
    {
        $email = 'failed-persistence@example.test';
        $outcome = [
            'classification' => EmailRiskService::RESULT_MATCHED,
            'matched' => true,
            'promoted' => true,
            'previous_status' => 0,
            'result_status' => 3,
        ];
        $service = Mockery::mock(EmailRiskAuthService::class);
        $service->shouldReceive('prepareRegistration')->once()->andReturn($outcome);
        $service->shouldReceive('persistRegistration')->once()->andReturn([
            'status' => EmailRiskAuthService::PERSIST_FAILED,
        ]);
        $service->shouldNotReceive('recordRegistrationOutcome');
        $this->app->instance(EmailRiskAuthService::class, $service);

        $response = $this->register($email, null, '198.51.100.10');

        $response->assertStatus(500)->assertJsonFragment(['message' => __('Register failed')]);
        $this->assertNull(User::where('email', $email)->first());
        $this->assertSame(0, DB::table('v2_log')->count());
    }

    /**
     * 验证邮件缓存故障放行注册并产生稳定脱敏警告。
     *
     * @dataProvider unusableEmailSnapshotProvider
     */
    public function testEmailSnapshotFailureAllowsRegistrationWithWarning(
        bool $storeSnapshot,
        $snapshot,
        string $errorCategory
    ): void {
        config(['v2board.email_risk_blacklist_enable' => 1]);
        if ($storeSnapshot) {
            Cache::put(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'), $snapshot);
        }
        $email = $errorCategory . '@example.test';

        $response = $this->register($email, null, '198.51.100.10');

        $response->assertOk();
        $user = User::where('email', $email)->firstOrFail();
        $this->assertSame(0, (int)$user->verification_status);
        $this->assertEmailAudit($user, $errorCategory, 'WARNING', 0, 0, $errorCategory);
    }

    /**
     * 提供邮件快照缺失和损坏的注册故障用例。
     */
    public function unusableEmailSnapshotProvider(): array
    {
        return [
            'missing' => [false, null, EmailRiskService::RESULT_SNAPSHOT_MISSING],
            'corrupt' => [true, ['version' => 1, 'rules' => ['UNKNOWN,value']], EmailRiskService::RESULT_SNAPSHOT_CORRUPT],
        ];
    }

    /**
     * 验证禁用和正常未命中不会改变注册或产生邮件事件。
     *
     * @dataProvider inactiveEmailRiskProvider
     */
    public function testInactiveEmailRiskPreservesOrdinaryRegistration(
        bool $enabled,
        bool $storeSnapshot
    ): void {
        config(['v2board.email_risk_blacklist_enable' => $enabled ? 1 : 0]);
        if ($storeSnapshot) {
            $this->installEmailSnapshot(['NAME,other-user@example.test']);
        }
        $email = ($enabled ? 'nonmatch' : 'disabled') . '@example.test';

        $response = $this->register($email, null, '198.51.100.10');

        $response->assertOk();
        $user = User::where('email', $email)->firstOrFail();
        $this->assertSame(0, (int)$user->verification_status);
        $this->assertSessionCreated($user, '198.51.100.10');
        $this->assertSame(0, DB::table('v2_log')->count());
    }

    /**
     * 提供邮件风控禁用和启用未命中的注册用例。
     */
    public function inactiveEmailRiskProvider(): array
    {
        return [
            'disabled' => [false, true],
            'not matched' => [true, true],
        ];
    }

    /**
     * 验证三个认证入口在五种 IP 风控结果下保持预期状态。
     *
     * @dataProvider authenticationIpOutcomeProvider
     */
    public function testAuthenticationIpOutcomeMatrix(
        string $entryPoint,
        bool $enabled,
        string $exceptions,
        string $clientIp,
        bool $matched
    ): void {
        config([
            'v2board.ip_risk_blacklist_enable' => $enabled ? 1 : 0,
            'v2board.ip_risk_exception_rules' => $exceptions,
        ]);

        if ($entryPoint === 'register') {
            $email = 'matrix-register@example.test';
            $response = $this->register($email, null, $clientIp);
            $user = User::where('email', $email)->firstOrFail();
            $previousStatus = 0;
        } else {
            $user = $this->createUser(['verification_status' => 2]);
            $previousStatus = 2;
            if ($entryPoint === 'password_login') {
                $response = $this->passwordLogin($user, $clientIp);
            } else {
                $verify = 'matrix-token-secret';
                Cache::put(CacheKey::get('TEMP_TOKEN', $verify), $user->id, 60);
                $response = $this->quickTokenLogin($verify, $clientIp);
            }
        }

        $response->assertOk();
        $this->assertAuthPayload($response->json('data'));
        $user->refresh();
        $expectedStatus = $matched ? 3 : $previousStatus;
        $this->assertSame($expectedStatus, (int)$user->verification_status);
        $this->assertSame($clientIp, $user->last_login_ip);
        $this->assertSessionCreated($user, $clientIp);
        if ($matched) {
            $this->assertMatchedAudit($entryPoint, $user, $previousStatus, $expectedStatus);
        } else {
            $this->assertSame(0, DB::table('v2_log')->count());
        }
    }

    /**
     * 提供三个入口的命中、例外、禁用、非法地址和未命中组合。
     */
    public function authenticationIpOutcomeProvider(): array
    {
        $rows = [];
        foreach (['register', 'password_login', 'token_login'] as $entryPoint) {
            $rows["{$entryPoint} matched"] = [$entryPoint, true, '', self::MATCHED_IP, true];
            $rows["{$entryPoint} exempt"] = [$entryPoint, true, '203.0.113.0/24', self::MATCHED_IP, false];
            $rows["{$entryPoint} disabled"] = [$entryPoint, false, '', self::MATCHED_IP, false];
            $rows["{$entryPoint} invalid IP"] = [$entryPoint, true, '', 'not-an-ip', false];
            $rows["{$entryPoint} non-match"] = [$entryPoint, true, '', '198.51.100.10', false];
        }

        return $rows;
    }

    /**
     * 验证命中 IP 的有效密码登录同步变红并保留原响应。
     */
    public function testMatchedPasswordLoginPersistsRedBeforeSuccessfulResponse(): void
    {
        $user = $this->createUser(['verification_status' => 2]);
        $this->bindFailIfCalledEmailRiskService();

        $response = $this->passwordLogin($user);

        $response->assertOk();
        $this->assertAuthPayload($response->json('data'));
        $user->refresh();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertSame(self::MATCHED_IP, $user->last_login_ip);
        $this->assertSessionCreated($user);
        $this->assertMatchedAudit('password_login', $user, 2, 3);
    }

    /**
     * 验证命中 IP 的有效快捷令牌登录同步变红并消费令牌。
     */
    public function testMatchedQuickTokenLoginPersistsRedBeforeSuccessfulResponse(): void
    {
        $user = $this->createUser(['verification_status' => 1]);
        $this->bindFailIfCalledEmailRiskService();
        $verify = 'quick-token-secret';
        $key = CacheKey::get('TEMP_TOKEN', $verify);
        Cache::put($key, $user->id, 60);

        $response = $this->quickTokenLogin($verify);

        $response->assertOk();
        $this->assertAuthPayload($response->json('data'));
        $user->refresh();
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertFalse(Cache::has($key));
        $this->assertSessionCreated($user);
        $this->assertMatchedAudit('token_login', $user, 1, 3, [$verify]);
    }

    /**
     * 验证密码和快捷登录对所有验证状态执行单调转换。
     *
     * @dataProvider matchedLoginStatusProvider
     */
    public function testMatchedLoginStatusMatrix(
        string $entryPoint,
        int $currentStatus,
        int $expectedStatus
    ): void {
        $user = $this->createUser(['verification_status' => $currentStatus]);
        if ($entryPoint === 'password_login') {
            $response = $this->passwordLogin($user);
        } else {
            $verify = "status-token-{$currentStatus}";
            Cache::put(CacheKey::get('TEMP_TOKEN', $verify), $user->id, 60);
            $response = $this->quickTokenLogin($verify);
        }

        $response->assertOk();
        $this->assertAuthPayload($response->json('data'));
        $user->refresh();
        $this->assertSame($expectedStatus, (int)$user->verification_status);
        $this->assertMatchedAudit($entryPoint, $user, $currentStatus, $expectedStatus);
    }

    /**
     * 提供密码和快捷登录的五级验证状态组合。
     */
    public function matchedLoginStatusProvider(): array
    {
        $rows = [];
        foreach (['password_login', 'token_login'] as $entryPoint) {
            foreach ([0 => 3, 1 => 3, 2 => 3, 3 => 3, 4 => 4] as $current => $expected) {
                $rows["{$entryPoint} status {$current}"] = [$entryPoint, $current, $expected];
            }
        }

        return $rows;
    }

    /**
     * 验证错误密码不会调用风控服务或改变用户状态。
     */
    public function testWrongPasswordDoesNotInvokeRiskEnforcement(): void
    {
        $user = $this->createUser(['verification_status' => 2]);
        $service = Mockery::mock(IpRiskAuthService::class);
        $service->shouldNotReceive('enforceLogin');
        $this->app->instance(IpRiskAuthService::class, $service);

        $response = $this->withServerVariables(['REMOTE_ADDR' => self::MATCHED_IP])
            ->postJson('/api/v1/passport/auth/login', [
                'email' => $user->email,
                'password' => 'incorrect-password',
            ]);

        $response->assertStatus(500);
        $this->assertSame(2, (int)$user->fresh()->verification_status);
        $this->assertSame(0, DB::table('v2_log')->count());
    }

    /**
     * 验证封禁账户不会调用风控服务或改变用户状态。
     */
    public function testBannedPasswordUserDoesNotInvokeRiskEnforcement(): void
    {
        $user = $this->createUser(['verification_status' => 2, 'banned' => 1]);
        $service = Mockery::mock(IpRiskAuthService::class);
        $service->shouldNotReceive('enforceLogin');
        $this->app->instance(IpRiskAuthService::class, $service);

        $response = $this->passwordLogin($user);

        $response->assertStatus(500);
        $this->assertSame(2, (int)$user->fresh()->verification_status);
        $this->assertSame(0, DB::table('v2_log')->count());
    }

    /**
     * 验证无效快捷令牌不会调用风控服务或写入审计。
     */
    public function testInvalidQuickTokenDoesNotInvokeRiskEnforcement(): void
    {
        $service = Mockery::mock(IpRiskAuthService::class);
        $service->shouldNotReceive('enforceLogin');
        $this->app->instance(IpRiskAuthService::class, $service);

        $response = $this->quickTokenLogin('unknown-token');

        $response->assertStatus(500);
        $this->assertSame(0, DB::table('v2_log')->count());
    }

    /**
     * 验证指向缺失用户的快捷令牌不会调用风控服务。
     */
    public function testQuickTokenForMissingUserDoesNotInvokeRiskEnforcement(): void
    {
        $verify = 'missing-user-token';
        Cache::put(CacheKey::get('TEMP_TOKEN', $verify), 99999, 60);
        $service = Mockery::mock(IpRiskAuthService::class);
        $service->shouldNotReceive('enforceLogin');
        $this->app->instance(IpRiskAuthService::class, $service);

        $response = $this->quickTokenLogin($verify);

        $response->assertStatus(500);
        $this->assertSame(0, DB::table('v2_log')->count());
    }

    /**
     * 验证封禁用户的快捷令牌不会调用风控服务。
     */
    public function testBannedQuickTokenUserDoesNotInvokeRiskEnforcement(): void
    {
        $user = $this->createUser(['verification_status' => 2, 'banned' => 1]);
        $verify = 'banned-user-token';
        Cache::put(CacheKey::get('TEMP_TOKEN', $verify), $user->id, 60);
        $service = Mockery::mock(IpRiskAuthService::class);
        $service->shouldNotReceive('enforceLogin');
        $this->app->instance(IpRiskAuthService::class, $service);

        $response = $this->quickTokenLogin($verify);

        $response->assertStatus(500);
        $this->assertSame(2, (int)$user->fresh()->verification_status);
        $this->assertSame(0, DB::table('v2_log')->count());
    }

    /**
     * 验证分类器异常不会阻断有效密码登录且只记录固定警告。
     */
    public function testClassifierFailureAllowsValidPasswordLogin(): void
    {
        $user = $this->createUser(['verification_status' => 2]);
        $classifier = Mockery::mock(IpRiskService::class);
        $classifier->shouldReceive('isBlacklisted')->once()->andThrow(new \RuntimeException('classifier secret'));
        $this->app->instance(IpRiskService::class, $classifier);

        $response = $this->passwordLogin($user);

        $response->assertOk();
        $this->assertAuthPayload($response->json('data'));
        $user->refresh();
        $this->assertSame(2, (int)$user->verification_status);
        $this->assertSame(self::MATCHED_IP, $user->last_login_ip);
        $this->assertSessionCreated($user);
        $this->assertFailureAudit('password_login', $user, 'WARNING', 'classifier_failure');
    }

    /**
     * 创建认证测试所需的最小数据表。
     */
    private function createTables(): void
    {
        Schema::create('v2_user', function (Blueprint $table): void {
            $table->increments('id');
            $table->unsignedInteger('invite_user_id')->nullable();
            $table->string('email')->unique();
            $table->string('password');
            $table->string('password_algo')->nullable();
            $table->string('password_salt')->nullable();
            $table->unsignedBigInteger('u')->default(0);
            $table->unsignedBigInteger('d')->default(0);
            $table->unsignedBigInteger('transfer_enable')->default(0);
            $table->unsignedTinyInteger('banned')->default(0);
            $table->unsignedTinyInteger('is_admin')->default(0);
            $table->unsignedTinyInteger('is_staff')->default(0);
            $table->unsignedTinyInteger('verification_status')->default(0);
            $table->string('uuid');
            $table->string('token')->unique();
            $table->unsignedInteger('group_id')->nullable();
            $table->unsignedInteger('plan_id')->nullable();
            $table->unsignedInteger('speed_limit')->nullable();
            $table->unsignedInteger('device_limit')->nullable();
            $table->unsignedBigInteger('expired_at')->nullable();
            $table->unsignedBigInteger('last_login_at')->nullable();
            $table->string('last_login_ip')->nullable();
            $table->unsignedBigInteger('created_at');
            $table->unsignedBigInteger('updated_at');
        });
        Schema::create('v2_invite_code', function (Blueprint $table): void {
            $table->increments('id');
            $table->unsignedInteger('user_id');
            $table->string('code')->unique();
            $table->unsignedTinyInteger('status')->default(0);
            $table->unsignedInteger('pv')->default(0);
            $table->unsignedBigInteger('created_at');
            $table->unsignedBigInteger('updated_at');
        });
        Schema::create('v2_log', function (Blueprint $table): void {
            $table->increments('id');
            $table->text('title');
            $table->string('level')->nullable();
            $table->string('host')->nullable();
            $table->string('uri');
            $table->string('method');
            $table->text('data')->nullable();
            $table->string('ip')->nullable();
            $table->text('context')->nullable();
            $table->unsignedBigInteger('created_at');
            $table->unsignedBigInteger('updated_at');
        });
    }

    /**
     * 安装版本一的缓存黑名单快照。
     */
    private function installSnapshot(array $rules): void
    {
        Cache::put(CacheKey::get('IP_RISK_BLACKLIST_SNAPSHOT', 'current'), [
            'version' => 1,
            'rules' => $rules,
            'updated_at' => time(),
        ]);
    }

    /**
     * 安装版本一的缓存邮件黑名单快照。
     */
    private function installEmailSnapshot(array $rules): void
    {
        Cache::put(CacheKey::get('EMAIL_RISK_BLACKLIST_SNAPSHOT', 'current'), [
            'version' => 1,
            'rules' => $rules,
            'updated_at' => time(),
        ]);
    }

    /**
     * 创建具备有效认证字段的用户。
     */
    private function createUser(array $attributes = []): User
    {
        $sequence = User::count() + 1;
        $user = new User();
        $user->forceFill(array_merge([
            'email' => "user{$sequence}@example.test",
            'password' => password_hash(self::PASSWORD, PASSWORD_DEFAULT),
            'password_algo' => null,
            'password_salt' => null,
            'uuid' => sprintf('00000000-0000-4000-8000-%012d', $sequence),
            'token' => md5("phase3-user-{$sequence}"),
            'verification_status' => 0,
            'banned' => 0,
            'is_admin' => 0,
            'is_staff' => 0,
            'u' => 0,
            'd' => 0,
            'transfer_enable' => 1024,
            'expired_at' => time() + 3600,
        ], $attributes));
        $user->save();

        return $user;
    }

    /**
     * 创建属于指定邀请人的有效邀请码。
     */
    private function createInvite(User $inviter): InviteCode
    {
        $invite = new InviteCode();
        $invite->user_id = $inviter->id;
        $invite->code = md5('invite-' . $inviter->id);
        $invite->status = 0;
        $invite->pv = 0;
        $invite->save();

        return $invite;
    }

    /**
     * 从固定客户端地址提交注册请求。
     */
    private function register(
        string $email,
        ?string $inviteCode = null,
        string $clientIp = self::MATCHED_IP
    )
    {
        $payload = ['email' => $email, 'password' => self::PASSWORD];
        if ($inviteCode !== null) {
            $payload['invite_code'] = $inviteCode;
        }

        return $this->withServerVariables(['REMOTE_ADDR' => $clientIp])
            ->postJson('/api/v1/passport/auth/register', $payload);
    }

    /**
     * 从固定客户端地址提交有效密码登录请求。
     */
    private function passwordLogin(User $user, string $clientIp = self::MATCHED_IP)
    {
        return $this->withServerVariables(['REMOTE_ADDR' => $clientIp])
            ->postJson('/api/v1/passport/auth/login', [
                'email' => $user->email,
                'password' => self::PASSWORD,
            ]);
    }

    /**
     * 从固定客户端地址提交快捷令牌登录请求。
     */
    private function quickTokenLogin(string $verify, string $clientIp = self::MATCHED_IP)
    {
        return $this->withServerVariables(['REMOTE_ADDR' => $clientIp])
            ->getJson('/api/v1/passport/auth/token2Login?verify=' . urlencode($verify));
    }

    /**
     * 断言成功响应保留完整认证字段。
     */
    private function assertAuthPayload(array $data): void
    {
        $this->assertArrayHasKey('token', $data);
        $this->assertArrayHasKey('is_admin', $data);
        $this->assertArrayHasKey('auth_data', $data);
        $this->assertNotSame('', $data['auth_data']);
    }

    /**
     * 断言用户成功建立一条带客户端地址的会话。
     */
    private function assertSessionCreated(User $user, string $clientIp = self::MATCHED_IP): void
    {
        $sessions = Cache::get(CacheKey::get('USER_SESSIONS', $user->id), []);
        $this->assertCount(1, $sessions);
        $this->assertSame($clientIp, array_values($sessions)[0]['ip']);
    }

    /**
     * 断言命中日志字段固定且不包含认证秘密。
     */
    private function assertMatchedAudit(
        string $entryPoint,
        User $user,
        int $previousStatus,
        int $resultStatus,
        array $extraSecrets = []
    ): void {
        $rows = DB::table('v2_log')->get();
        $this->assertCount(1, $rows);
        $row = $rows->first();
        $this->assertSame('INFO', $row->level);
        $this->assertSame('risk:authentication-enforcement', $row->uri);
        $this->assertSame('SYSTEM', $row->method);
        $this->assertSame('{}', $row->data);
        $context = json_decode($row->context, true);
        $this->assertSame($entryPoint, $context['entry_point']);
        $this->assertSame($user->id, $context['user_id']);
        $this->assertSame(self::MATCHED_IP, $context['client_ip']);
        $this->assertSame($previousStatus, $context['previous_status']);
        $this->assertSame($resultStatus, $context['result_status']);
        $serialized = json_encode(['row' => (array)$row, 'context' => $context]);
        foreach (array_merge([$user->email, self::PASSWORD, $user->token], $extraSecrets) as $secret) {
            $this->assertStringNotContainsString($secret, $serialized);
        }
        foreach (['password', 'token', 'auth_data', 'authorization', 'request'] as $forbiddenKey) {
            $this->assertArrayNotHasKey($forbiddenKey, $context);
        }
    }

    /**
     * 断言风控失败日志使用固定分类且不泄露异常内容。
     */
    private function assertFailureAudit(
        string $entryPoint,
        User $user,
        string $level,
        string $errorCategory
    ): void {
        $rows = DB::table('v2_log')->get();
        $this->assertCount(1, $rows);
        $row = $rows->first();
        $this->assertSame($level, $row->level);
        $this->assertSame('{}', $row->data);
        $context = json_decode($row->context, true);
        $this->assertSame($entryPoint, $context['entry_point']);
        $this->assertSame($user->id, $context['user_id']);
        $this->assertSame($errorCategory, $context['error_category']);
        $this->assertStringNotContainsString('classifier secret', json_encode((array)$row));
        $this->assertArrayNotHasKey('exception', $context);
        $this->assertArrayNotHasKey('trace', $context);
    }

    /**
     * 断言邮件注册风控事件字段固定且不包含认证或规则秘密。
     */
    private function assertEmailAudit(
        User $user,
        string $event,
        string $level,
        int $previousStatus,
        int $resultStatus,
        ?string $errorCategory = null,
        array $extraSecrets = []
    ): void {
        $rows = DB::table('v2_log')
            ->where('uri', 'risk:email-registration-enforcement')
            ->get();
        $this->assertCount(1, $rows);
        $row = $rows->first();
        $this->assertSame($level, $row->level);
        $this->assertSame('SYSTEM', $row->method);
        $this->assertSame('{}', $row->data);
        $this->assertSame('', $row->ip);
        $context = json_decode($row->context, true);
        $this->assertSame($event, $context['event']);
        $this->assertSame('email', $context['risk_domain']);
        $this->assertSame('register', $context['entry_point']);
        $this->assertSame($user->id, $context['user_id']);
        $this->assertSame($previousStatus, $context['previous_status']);
        $this->assertSame($resultStatus, $context['result_status']);
        if ($errorCategory === null) {
            $this->assertArrayNotHasKey('error_category', $context);
        } else {
            $this->assertSame($errorCategory, $context['error_category']);
        }
        $serialized = (string)json_encode(['row' => (array)$row, 'context' => $context]);
        foreach (array_merge([$user->email, self::PASSWORD, $user->token], $extraSecrets) as $secret) {
            $this->assertStringNotContainsString($secret, $serialized);
        }
        foreach (['password', 'token', 'auth_data', 'authorization', 'request', 'rule'] as $forbiddenKey) {
            $this->assertArrayNotHasKey($forbiddenKey, $context);
        }
    }

    /**
     * 绑定任何注册邮件风控调用都会使现有用户登录测试失败的服务。
     */
    private function bindFailIfCalledEmailRiskService(): void
    {
        $service = Mockery::mock(EmailRiskAuthService::class);
        $service->shouldNotReceive('prepareRegistration');
        $service->shouldNotReceive('persistRegistration');
        $service->shouldNotReceive('recordRegistrationOutcome');
        $this->app->instance(EmailRiskAuthService::class, $service);
    }

    /**
     * 断言指定风控域仅写入一个固定脱敏事件。
     */
    private function assertDomainAudit(
        string $uri,
        string $event,
        string $level,
        ?int $userId,
        array $extraSecrets = []
    ): void {
        $rows = DB::table('v2_log')->where('uri', $uri)->get();
        $this->assertCount(1, $rows);
        $row = $rows->first();
        $context = json_decode($row->context, true);
        $this->assertSame($level, $row->level);
        $this->assertSame($event, $context['event']);
        $this->assertSame($userId, $context['user_id']);
        $serialized = (string)json_encode(['row' => (array)$row, 'context' => $context]);
        foreach ($extraSecrets as $secret) {
            $this->assertStringNotContainsString($secret, $serialized);
        }
    }
}
