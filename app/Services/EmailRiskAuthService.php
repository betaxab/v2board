<?php

namespace App\Services;

use App\Models\Log as LogModel;
use App\Models\User;
use Illuminate\Support\Facades\Log;

class EmailRiskAuthService
{
    public const PERSIST_SAVED = 'saved';
    public const PERSIST_FALLBACK_SAVED = 'fallback_saved';
    public const PERSIST_FAILED = 'failed';

    private const ENTRY_REGISTER = 'register';

    private $riskService;
    private $logRecorder;
    private $fallbackRecorder;

    /**
     * 注入邮件分类器以及主审计和固定降级日志记录器。
     */
    public function __construct(
        ?EmailRiskService $riskService = null,
        ?callable $logRecorder = null,
        ?callable $fallbackRecorder = null
    ) {
        $this->riskService = $riskService ?: new EmailRiskService();
        $this->logRecorder = $logRecorder ?: function (array $record): void {
            LogModel::insert($record);
        };
        $this->fallbackRecorder = $fallbackRecorder ?: function (): void {
            Log::channel('daily')->warning('邮件风险审计写入失败', [
                'error_category' => 'audit_failure',
            ]);
        };
    }

    /**
     * 在注册首次保存前计算邮件风险并单调提升验证状态。
     */
    public function prepareRegistration(User $user, string $email): array
    {
        $previousStatus = (int)$user->verification_status;
        try {
            $classification = $this->riskService->classify($email);
        } catch (\Throwable $exception) {
            return $this->outcome(
                'classifier_failure',
                false,
                false,
                $previousStatus,
                $previousStatus
            );
        }

        $classificationStatus = (string)($classification['status'] ?? 'classifier_failure');
        $matched = ($classification['matched'] ?? false) === true;
        if (!$this->isValidClassification($classificationStatus, $matched)) {
            return $this->outcome(
                'classifier_failure',
                false,
                false,
                $previousStatus,
                $previousStatus
            );
        }
        if (!$matched) {
            return $this->outcome(
                $classificationStatus,
                false,
                false,
                $previousStatus,
                $previousStatus
            );
        }

        $resultStatus = max($previousStatus, 3);
        $user->verification_status = $resultStatus;

        return $this->outcome(
            EmailRiskService::RESULT_MATCHED,
            true,
            $resultStatus !== $previousStatus,
            $previousStatus,
            $resultStatus
        );
    }

    /**
     * 保存注册用户，并在安全条件满足时仅移除邮件提升后重试一次。
     */
    public function persistRegistration(User $user, array $outcome): array
    {
        if ($this->saveUser($user)) {
            return ['status' => self::PERSIST_SAVED];
        }

        if (($outcome['promoted'] ?? false) !== true || $user->exists) {
            return ['status' => self::PERSIST_FAILED];
        }

        $user->verification_status = (int)($outcome['previous_status'] ?? 0);
        if ($this->saveUser($user)) {
            return ['status' => self::PERSIST_FALLBACK_SAVED];
        }

        return ['status' => self::PERSIST_FAILED];
    }

    /**
     * 在用户已持久化后记录邮件命中、缓存故障和保存降级事件。
     */
    public function recordRegistrationOutcome(User $user, array $outcome, array $persistence): void
    {
        $classification = (string)($outcome['classification'] ?? 'classifier_failure');
        $previousStatus = (int)($outcome['previous_status'] ?? 0);
        $persistedStatus = (int)$user->verification_status;

        if (($outcome['matched'] ?? false) === true) {
            $this->recordEvent(
                'matched',
                'INFO',
                $user,
                $previousStatus,
                $persistedStatus
            );
        } elseif (in_array($classification, [
            EmailRiskService::RESULT_SNAPSHOT_MISSING,
            EmailRiskService::RESULT_SNAPSHOT_CORRUPT,
            'classifier_failure',
        ], true)) {
            $this->recordEvent(
                $classification,
                'WARNING',
                $user,
                $previousStatus,
                $persistedStatus,
                $classification
            );
        }

        if (($persistence['status'] ?? null) === self::PERSIST_FALLBACK_SAVED
            && ($outcome['matched'] ?? false) === true) {
            $this->recordEvent(
                'persistence_failure',
                'ERROR',
                $user,
                $previousStatus,
                $persistedStatus,
                'persistence_failure'
            );
        }
    }

    /**
     * 构造不包含邮箱、规则或异常内容的注册分类结果。
     */
    private function outcome(
        string $classification,
        bool $matched,
        bool $promoted,
        int $previousStatus,
        int $resultStatus
    ): array {
        return [
            'classification' => $classification,
            'matched' => $matched,
            'promoted' => $promoted,
            'previous_status' => $previousStatus,
            'result_status' => $resultStatus,
        ];
    }

    /**
     * 将用户保存的返回值或异常收敛为固定布尔结果。
     */
    private function saveUser(User $user): bool
    {
        try {
            return $user->save() === true;
        } catch (\Throwable $exception) {
            return false;
        }
    }

    /**
     * 仅接受固定分类状态以及与状态一致的命中标记。
     */
    private function isValidClassification(string $status, bool $matched): bool
    {
        $allowed = [
            EmailRiskService::RESULT_DISABLED,
            EmailRiskService::RESULT_SNAPSHOT_MISSING,
            EmailRiskService::RESULT_SNAPSHOT_CORRUPT,
            EmailRiskService::RESULT_NOT_MATCHED,
            EmailRiskService::RESULT_MATCHED,
        ];

        return in_array($status, $allowed, true)
            && $matched === ($status === EmailRiskService::RESULT_MATCHED);
    }

    /**
     * 直接写入固定字段的邮件注册风控事件并隔离审计故障。
     */
    private function recordEvent(
        string $event,
        string $level,
        User $user,
        int $previousStatus,
        int $resultStatus,
        ?string $errorCategory = null
    ): void {
        $context = [
            'event' => $event,
            'risk_domain' => 'email',
            'entry_point' => self::ENTRY_REGISTER,
            'user_id' => $this->userId($user),
            'previous_status' => $previousStatus,
            'result_status' => $resultStatus,
        ];
        if ($errorCategory !== null) {
            $context['error_category'] = $errorCategory;
        }
        $encodedContext = json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($encodedContext)) {
            $encodedContext = '{}';
        }
        $timestamp = time();

        try {
            call_user_func($this->logRecorder, [
                'title' => $this->eventTitle($event),
                'level' => $level,
                'host' => 'system',
                'uri' => 'risk:email-registration-enforcement',
                'method' => 'SYSTEM',
                'data' => '{}',
                'ip' => '',
                'context' => $encodedContext,
                'created_at' => $timestamp,
                'updated_at' => $timestamp,
            ]);
        } catch (\Throwable $exception) {
            try {
                call_user_func($this->fallbackRecorder);
            } catch (\Throwable $fallbackException) {
                // 审计降级日志失败不能改变注册结果。
            }
        }
    }

    /**
     * 返回邮件注册风控事件对应的固定标题。
     */
    private function eventTitle(string $event): string
    {
        if ($event === 'matched') {
            return '邮件风险注册命中';
        }
        if ($event === 'persistence_failure') {
            return '邮件风险注册状态保存失败';
        }

        return '邮件风险注册分类失败';
    }

    /**
     * 返回已持久化用户 ID，未保存用户返回空值。
     */
    private function userId(User $user): ?int
    {
        $userId = $user->getKey();

        return $userId === null ? null : (int)$userId;
    }
}
