<?php

namespace Tests\Unit;

use App\Models\User;
use App\Services\EmailRiskAuthService;
use App\Services\EmailRiskService;
use Mockery;
use RuntimeException;
use Tests\TestCase;

class EmailRiskAuthServiceTest extends TestCase
{
    /**
     * 验证邮件命中按单调规则更新状态并返回固定结果。
     *
     * @dataProvider registrationStatusProvider
     */
    public function testPrepareRegistrationAppliesMonotonicStatus(
        int $current,
        int $expected,
        bool $promoted
    ): void {
        $classifier = Mockery::mock(EmailRiskService::class);
        $classifier->shouldReceive('classify')->once()->with('user@example.test')->andReturn([
            'status' => EmailRiskService::RESULT_MATCHED,
            'matched' => true,
        ]);
        $user = new User();
        $user->verification_status = $current;

        $outcome = (new EmailRiskAuthService($classifier))->prepareRegistration(
            $user,
            'user@example.test'
        );

        $this->assertSame($expected, (int)$user->verification_status);
        $this->assertSame([
            'classification' => EmailRiskService::RESULT_MATCHED,
            'matched' => true,
            'promoted' => $promoted,
            'previous_status' => $current,
            'result_status' => $expected,
        ], $outcome);
    }

    /**
     * 提供邮件命中时的状态提升和深色保留用例。
     */
    public function registrationStatusProvider(): array
    {
        return [
            'grey to red' => [0, 3, true],
            'green to red' => [2, 3, true],
            'red unchanged' => [3, 3, false],
            'dark unchanged' => [4, 4, false],
        ];
    }

    /**
     * 验证分类异常只返回固定故障类别且不泄露异常文本。
     */
    public function testClassifierFailureFailsOpenWithSanitizedOutcome(): void
    {
        $classifier = Mockery::mock(EmailRiskService::class);
        $classifier->shouldReceive('classify')->once()
            ->andThrow(new RuntimeException('classifier-sensitive-value'));
        $user = new User();
        $user->verification_status = 2;

        $outcome = (new EmailRiskAuthService($classifier))->prepareRegistration(
            $user,
            'sensitive-user@example.test'
        );

        $this->assertSame(2, (int)$user->verification_status);
        $this->assertSame('classifier_failure', $outcome['classification']);
        $this->assertFalse($outcome['matched']);
        $encoded = (string)json_encode($outcome);
        $this->assertStringNotContainsString('sensitive-user@example.test', $encoded);
        $this->assertStringNotContainsString('classifier-sensitive-value', $encoded);
    }

    /**
     * 验证分类异常在用户持久化后写入固定脱敏警告。
     */
    public function testClassifierFailureRecordsSanitizedWarningAfterPersistence(): void
    {
        $records = [];
        $classifier = Mockery::mock(EmailRiskService::class);
        $classifier->shouldReceive('classify')->once()
            ->andThrow(new RuntimeException('classifier-sensitive-value'));
        $user = new User();
        $user->id = 16;
        $user->email = 'sensitive-user@example.test';
        $user->verification_status = 2;
        $service = new EmailRiskAuthService(
            $classifier,
            function (array $record) use (&$records): void {
                $records[] = $record;
            }
        );

        $outcome = $service->prepareRegistration($user, $user->email);
        $service->recordRegistrationOutcome(
            $user,
            $outcome,
            ['status' => EmailRiskAuthService::PERSIST_SAVED]
        );

        $this->assertCount(1, $records);
        $this->assertSame('WARNING', $records[0]['level']);
        $context = json_decode($records[0]['context'], true);
        $this->assertSame('classifier_failure', $context['event']);
        $this->assertSame('classifier_failure', $context['error_category']);
        $encoded = (string)json_encode($records);
        $this->assertStringNotContainsString($user->email, $encoded);
        $this->assertStringNotContainsString('classifier-sensitive-value', $encoded);
    }

    /**
     * 验证首次保存成功时不会执行降级重试。
     */
    public function testSuccessfulPersistenceSavesExactlyOnce(): void
    {
        $user = Mockery::mock(User::class)->makePartial();
        $user->verification_status = 3;
        $user->shouldReceive('save')->once()->andReturnTrue();

        $result = (new EmailRiskAuthService())->persistRegistration($user, [
            'promoted' => true,
            'previous_status' => 0,
        ]);

        $this->assertSame(['status' => EmailRiskAuthService::PERSIST_SAVED], $result);
        $this->assertSame(3, (int)$user->verification_status);
    }

    /**
     * 验证安全的首次保存失败会移除邮件提升并仅重试一次。
     */
    public function testFailedFirstSaveFallsBackToPreviousStatusOnce(): void
    {
        $user = Mockery::mock(User::class)->makePartial();
        $user->exists = false;
        $user->verification_status = 3;
        $user->shouldReceive('save')->twice()->andReturn(false, true);

        $result = (new EmailRiskAuthService())->persistRegistration($user, [
            'promoted' => true,
            'previous_status' => 2,
        ]);

        $this->assertSame(['status' => EmailRiskAuthService::PERSIST_FALLBACK_SAVED], $result);
        $this->assertSame(2, (int)$user->verification_status);
    }

    /**
     * 验证首次保存抛出异常时仍只执行一次安全降级保存。
     */
    public function testThrowingFirstSaveFallsBackExactlyOnce(): void
    {
        $user = Mockery::mock(User::class)->makePartial();
        $user->exists = false;
        $user->verification_status = 3;
        $user->shouldReceive('save')->once()->ordered()
            ->andThrow(new RuntimeException('save-exception-sentinel'));
        $user->shouldReceive('save')->once()->ordered()->andReturnTrue();

        $result = (new EmailRiskAuthService())->persistRegistration($user, [
            'promoted' => true,
            'previous_status' => 2,
        ]);

        $this->assertSame(['status' => EmailRiskAuthService::PERSIST_FALLBACK_SAVED], $result);
        $this->assertSame(2, (int)$user->verification_status);
        $this->assertStringNotContainsString('save-exception-sentinel', (string)json_encode($result));
    }

    /**
     * 验证第二次保存返回失败或抛出异常后停止且不超过两次。
     *
     * @dataProvider fallbackFailureProvider
     * @param bool|\Throwable $fallbackResult
     */
    public function testFallbackFailureStopsAfterTwoSaves($fallbackResult): void
    {
        $user = Mockery::mock(User::class)->makePartial();
        $user->exists = false;
        $user->verification_status = 3;
        $user->shouldReceive('save')->once()->ordered()->andReturnFalse();
        $fallback = $user->shouldReceive('save')->once()->ordered();
        if ($fallbackResult instanceof \Throwable) {
            $fallback->andThrow($fallbackResult);
        } else {
            $fallback->andReturn($fallbackResult);
        }

        $result = (new EmailRiskAuthService())->persistRegistration($user, [
            'promoted' => true,
            'previous_status' => 2,
        ]);

        $this->assertSame(['status' => EmailRiskAuthService::PERSIST_FAILED], $result);
        $this->assertSame(2, (int)$user->verification_status);
        $this->assertStringNotContainsString('fallback-exception-sentinel', (string)json_encode($result));
    }

    /**
     * 提供降级保存返回失败和抛出异常用例。
     */
    public function fallbackFailureProvider(): array
    {
        return [
            'false' => [false],
            'exception' => [new RuntimeException('fallback-exception-sentinel')],
        ];
    }

    /**
     * 验证未实际提升状态的分类结果不会触发降级保存。
     *
     * @dataProvider noPromotionOutcomeProvider
     */
    public function testNoPromotionNeverRetriesPersistence(array $outcome, int $status): void
    {
        $user = Mockery::mock(User::class)->makePartial();
        $user->exists = false;
        $user->verification_status = $status;
        $user->shouldReceive('save')->once()->andReturnFalse();

        $result = (new EmailRiskAuthService())->persistRegistration($user, $outcome);

        $this->assertSame(['status' => EmailRiskAuthService::PERSIST_FAILED], $result);
        $this->assertSame($status, (int)$user->verification_status);
    }

    /**
     * 提供未命中、已红、已深和分类失败的无提升结果。
     */
    public function noPromotionOutcomeProvider(): array
    {
        return [
            'not matched' => [[
                'classification' => EmailRiskService::RESULT_NOT_MATCHED,
                'matched' => false,
                'promoted' => false,
                'previous_status' => 2,
                'result_status' => 2,
            ], 2],
            'already red' => [[
                'classification' => EmailRiskService::RESULT_MATCHED,
                'matched' => true,
                'promoted' => false,
                'previous_status' => 3,
                'result_status' => 3,
            ], 3],
            'already dark' => [[
                'classification' => EmailRiskService::RESULT_MATCHED,
                'matched' => true,
                'promoted' => false,
                'previous_status' => 4,
                'result_status' => 4,
            ], 4],
            'classifier failure' => [[
                'classification' => 'classifier_failure',
                'matched' => false,
                'promoted' => false,
                'previous_status' => 2,
                'result_status' => 2,
            ], 2],
        ];
    }

    /**
     * 验证插入后异常标记模型存在时不重试且仍可记录真实命中。
     */
    public function testPostInsertFailureDoesNotRetryAndRecordsPersistedOutcome(): void
    {
        $records = [];
        $user = Mockery::mock(User::class)->makePartial();
        $user->id = 91;
        $user->exists = false;
        $user->verification_status = 3;
        $user->shouldReceive('save')->once()->andReturnUsing(function () use ($user): void {
            $user->exists = true;
            throw new RuntimeException('post-insert-exception-sentinel');
        });
        $service = new EmailRiskAuthService(null, function (array $record) use (&$records): void {
            $records[] = $record;
        });
        $outcome = [
            'classification' => EmailRiskService::RESULT_MATCHED,
            'matched' => true,
            'promoted' => true,
            'previous_status' => 2,
            'result_status' => 3,
        ];

        $persistence = $service->persistRegistration($user, $outcome);
        $service->recordRegistrationOutcome($user, $outcome, $persistence);

        $this->assertSame(['status' => EmailRiskAuthService::PERSIST_FAILED], $persistence);
        $this->assertSame(3, (int)$user->verification_status);
        $this->assertCount(1, $records);
        $context = json_decode($records[0]['context'], true);
        $this->assertSame('matched', $context['event']);
        $this->assertSame(91, $context['user_id']);
        $this->assertStringNotContainsString(
            'post-insert-exception-sentinel',
            (string)json_encode([$persistence, $records])
        );
    }

    /**
     * 验证成功降级保存后按实际状态记录命中和持久化失败事件。
     */
    public function testFallbackSavedMatchRecordsTwoEventsWithPersistedBaseline(): void
    {
        $records = [];
        $user = new User();
        $user->id = 92;
        $user->verification_status = 2;
        $service = new EmailRiskAuthService(null, function (array $record) use (&$records): void {
            $records[] = $record;
        });

        $service->recordRegistrationOutcome($user, [
            'classification' => EmailRiskService::RESULT_MATCHED,
            'matched' => true,
            'promoted' => true,
            'previous_status' => 2,
            'result_status' => 3,
        ], ['status' => EmailRiskAuthService::PERSIST_FALLBACK_SAVED]);

        $this->assertCount(2, $records);
        $contexts = array_map(function (array $record): array {
            return json_decode($record['context'], true);
        }, $records);
        $this->assertSame(['matched', 'persistence_failure'], array_column($contexts, 'event'));
        $this->assertSame(['INFO', 'ERROR'], array_column($records, 'level'));
        $this->assertSame([2, 2], array_column($contexts, 'result_status'));
        $this->assertSame('persistence_failure', $contexts[1]['error_category']);
    }

    /**
     * 验证邮件命中事件只包含固定字段并使用独立审计 URI。
     */
    public function testRecordMatchedOutcomeWritesSanitizedFixedAudit(): void
    {
        $records = [];
        $user = new User();
        $user->id = 17;
        $user->email = 'sensitive-user@example.test';
        $user->token = 'sensitive-token';
        $user->verification_status = 3;
        $service = new EmailRiskAuthService(null, function (array $record) use (&$records): void {
            $records[] = $record;
        });

        $service->recordRegistrationOutcome($user, [
            'classification' => EmailRiskService::RESULT_MATCHED,
            'matched' => true,
            'promoted' => true,
            'previous_status' => 0,
            'result_status' => 3,
        ], ['status' => EmailRiskAuthService::PERSIST_SAVED]);

        $this->assertCount(1, $records);
        $this->assertSame('INFO', $records[0]['level']);
        $this->assertSame('risk:email-registration-enforcement', $records[0]['uri']);
        $this->assertSame('SYSTEM', $records[0]['method']);
        $this->assertSame('{}', $records[0]['data']);
        $this->assertSame('', $records[0]['ip']);
        $context = json_decode($records[0]['context'], true);
        $this->assertSame([
            'event',
            'risk_domain',
            'entry_point',
            'user_id',
            'previous_status',
            'result_status',
        ], array_keys($context));
        $this->assertSame('email', $context['risk_domain']);
        $this->assertSame('register', $context['entry_point']);
        $this->assertSame(17, $context['user_id']);
        $encoded = (string)json_encode($records);
        $this->assertStringNotContainsString($user->email, $encoded);
        $this->assertStringNotContainsString($user->token, $encoded);
    }

    /**
     * 验证主审计失败只触发一次固定降级记录且不会抛出。
     */
    public function testPrimaryAuditFailureInvokesFixedFallbackOnce(): void
    {
        $fallbackCount = 0;
        $user = new User();
        $user->id = 18;
        $user->verification_status = 0;
        $service = new EmailRiskAuthService(
            null,
            function (): void {
                throw new RuntimeException('primary-sensitive-value');
            },
            function () use (&$fallbackCount): void {
                $fallbackCount++;
            }
        );

        $service->recordRegistrationOutcome($user, [
            'classification' => EmailRiskService::RESULT_SNAPSHOT_MISSING,
            'matched' => false,
            'promoted' => false,
            'previous_status' => 0,
            'result_status' => 0,
        ], ['status' => EmailRiskAuthService::PERSIST_SAVED]);

        $this->assertSame(1, $fallbackCount);
    }

    /**
     * 验证每个失败主事件各触发一次无参数降级且降级异常被吞掉。
     */
    public function testEachPrimaryFailureInvokesOneArgumentFreeFallback(): void
    {
        $primaryCount = 0;
        $fallbackCount = 0;
        $fallbackArguments = [];
        $user = new User();
        $user->id = 93;
        $user->verification_status = 2;
        $service = new EmailRiskAuthService(
            null,
            function (array $record) use (&$primaryCount): void {
                $primaryCount++;
                throw new RuntimeException('recorder-exception-sentinel');
            },
            function (...$arguments) use (&$fallbackCount, &$fallbackArguments): void {
                $fallbackCount++;
                $fallbackArguments[] = $arguments;
                throw new RuntimeException('fallback-recorder-exception-sentinel');
            }
        );

        $service->recordRegistrationOutcome($user, [
            'classification' => EmailRiskService::RESULT_MATCHED,
            'matched' => true,
            'promoted' => true,
            'previous_status' => 2,
            'result_status' => 3,
        ], ['status' => EmailRiskAuthService::PERSIST_FALLBACK_SAVED]);

        $this->assertSame(2, $primaryCount);
        $this->assertSame(2, $fallbackCount);
        $this->assertSame([[], []], $fallbackArguments);
    }

    /**
     * 验证未知分类状态收敛为固定故障且所有运输对象拒绝敏感哨兵。
     */
    public function testOutcomesAndAuditTransportsRejectSensitiveSentinels(): void
    {
        $sentinels = [
            'candidate-email-sentinel@example.test',
            'rule-value-sentinel',
            'password-sentinel',
            'quick-token-sentinel',
            'authorization-sentinel',
            'request-field-sentinel',
            'classifier-exception-sentinel',
            'save-exception-sentinel',
            'recorder-exception-sentinel',
        ];
        $records = [];
        $fallbackCalls = [];
        $classifier = Mockery::mock(EmailRiskService::class);
        $classifier->shouldReceive('classify')->once()->andReturn([
            'status' => 'rule-value-sentinel',
            'matched' => false,
        ]);
        $user = new User();
        $user->id = 94;
        $user->email = $sentinels[0];
        $user->token = $sentinels[3];
        $user->verification_status = 2;
        $service = new EmailRiskAuthService(
            $classifier,
            function (array $record) use (&$records): void {
                $records[] = $record;
            },
            function () use (&$fallbackCalls): void {
                $fallbackCalls[] = func_get_args();
            }
        );

        $outcome = $service->prepareRegistration($user, $sentinels[0]);
        $service->recordRegistrationOutcome(
            $user,
            $outcome,
            ['status' => EmailRiskAuthService::PERSIST_SAVED]
        );

        $this->assertSame('classifier_failure', $outcome['classification']);
        $this->assertCount(1, $records);
        $this->assertSame([], $fallbackCalls);
        $serialized = (string)json_encode([$outcome, $records, $fallbackCalls]);
        foreach ($sentinels as $sentinel) {
            $this->assertStringNotContainsString($sentinel, $serialized);
        }
        $this->assertSame('{}', $records[0]['data']);
        $this->assertSame('', $records[0]['ip']);
    }
}
