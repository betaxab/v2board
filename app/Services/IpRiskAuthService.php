<?php

namespace App\Services;

use App\Models\Log as LogModel;
use App\Models\User;
use InvalidArgumentException;

class IpRiskAuthService
{
    public const ENTRY_REGISTER = 'register';
    public const ENTRY_PASSWORD_LOGIN = 'password_login';
    public const ENTRY_TOKEN_LOGIN = 'token_login';

    private $riskService;
    private $logRecorder;

    /**
     * 初始化认证风控分类器和可替换的脱敏日志记录器。
     */
    public function __construct(?IpRiskService $riskService = null, ?callable $logRecorder = null)
    {
        $this->riskService = $riskService ?: new IpRiskService();
        $this->logRecorder = $logRecorder ?: function (array $record): void {
            LogModel::insert($record);
        };
    }

    /**
     * 在注册首次保存前计算并写入最终验证状态。
     */
    public function prepareRegistration(User $user, ?string $clientIp): array
    {
        $clientIp = $clientIp ?? '';
        $previousStatus = (int)$user->verification_status;
        try {
            $matched = $this->riskService->isBlacklisted($clientIp);
        } catch (\Throwable $exception) {
            $this->recordEvent(
                'classifier_failure',
                'WARNING',
                self::ENTRY_REGISTER,
                $user,
                $clientIp,
                $previousStatus,
                $previousStatus,
                'classifier_failure'
            );

            return $this->outcome(false, $previousStatus, $previousStatus);
        }

        if (!$matched) {
            return $this->outcome(false, $previousStatus, $previousStatus);
        }

        $resultStatus = max($previousStatus, 3);
        $user->verification_status = $resultStatus;

        return $this->outcome(true, $previousStatus, $resultStatus);
    }

    /**
     * 在注册用户保存成功后记录一次正常黑名单命中。
     */
    public function recordRegistrationMatch(User $user, ?string $clientIp, array $outcome): void
    {
        if (($outcome['matched'] ?? false) !== true) {
            return;
        }

        $clientIp = $clientIp ?? '';

        $this->recordEvent(
            'matched',
            'INFO',
            self::ENTRY_REGISTER,
            $user,
            $clientIp,
            (int)$outcome['previous_status'],
            (int)$outcome['result_status']
        );
    }

    /**
     * 对成功登录执行单次分类和必要的同步状态保存。
     */
    public function enforceLogin(User $user, ?string $clientIp, string $entryPoint): void
    {
        if (!in_array($entryPoint, [self::ENTRY_PASSWORD_LOGIN, self::ENTRY_TOKEN_LOGIN], true)) {
            throw new InvalidArgumentException('Unsupported authentication risk entry point.');
        }

        $clientIp = $clientIp ?? '';
        $previousStatus = (int)$user->verification_status;
        try {
            $matched = $this->riskService->isBlacklisted($clientIp);
        } catch (\Throwable $exception) {
            $this->recordEvent(
                'classifier_failure',
                'WARNING',
                $entryPoint,
                $user,
                $clientIp,
                $previousStatus,
                $previousStatus,
                'classifier_failure'
            );
            return;
        }

        if (!$matched) {
            return;
        }

        $resultStatus = max($previousStatus, 3);
        if ($resultStatus !== $previousStatus) {
            $user->verification_status = $resultStatus;
            try {
                $saved = $user->save();
            } catch (\Throwable $exception) {
                $saved = false;
            }
            if (!$saved) {
                $user->verification_status = $previousStatus;
                $this->recordEvent(
                    'persistence_failure',
                    'ERROR',
                    $entryPoint,
                    $user,
                    $clientIp,
                    $previousStatus,
                    $previousStatus,
                    'persistence_failure'
                );
                return;
            }
        }

        $this->recordEvent(
            'matched',
            'INFO',
            $entryPoint,
            $user,
            $clientIp,
            $previousStatus,
            $resultStatus
        );
    }

    /**
     * 构造注册分类结果供首次保存和后置审计复用。
     */
    private function outcome(bool $matched, int $previousStatus, int $resultStatus): array
    {
        return [
            'matched' => $matched,
            'previous_status' => $previousStatus,
            'result_status' => $resultStatus,
        ];
    }

    /**
     * 直接写入固定字段的认证风控日志并隔离日志故障。
     */
    private function recordEvent(
        string $event,
        string $level,
        string $entryPoint,
        User $user,
        string $clientIp,
        int $previousStatus,
        int $resultStatus,
        ?string $errorCategory = null
    ): void {
        $context = [
            'event' => $event,
            'entry_point' => $entryPoint,
            'user_id' => $this->userId($user),
            'client_ip' => $clientIp,
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
                'uri' => 'risk:authentication-enforcement',
                'method' => 'SYSTEM',
                'data' => '{}',
                'ip' => $clientIp,
                'context' => $encodedContext,
                'created_at' => $timestamp,
                'updated_at' => $timestamp,
            ]);
        } catch (\Throwable $exception) {
            // 风控日志失败不能改变注册或登录结果。
        }
    }

    /**
     * 返回固定事件对应的日志标题。
     */
    private function eventTitle(string $event): string
    {
        if ($event === 'classifier_failure') {
            return 'IP 风险认证分类失败';
        }
        if ($event === 'persistence_failure') {
            return 'IP 风险认证状态保存失败';
        }

        return 'IP 风险认证命中';
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
