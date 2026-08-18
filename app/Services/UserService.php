<?php

namespace App\Services;

use App\Jobs\StatServerJob;
use App\Jobs\StatUserJob;
use App\Jobs\TrafficFetchJob;
use App\Models\Order;
use App\Models\Plan;
use App\Models\User;

class UserService
{
    public const USER_TYPE_NEW = 'new';
    public const USER_TYPE_OLD = 'old';

    private function calcResetDayByMonthFirstDay()
    {
        $today = date('d');
        $lastDay = date('d', strtotime('last day of +0 months'));
        return $lastDay - $today;
    }

    private function calcResetDayByExpireDay(int $expiredAt)
    {
        $day = date('d', $expiredAt);
        $today = date('d');
        $lastDay = date('d', strtotime('last day of +0 months'));
        if ((int)$day >= (int)$today && (int)$day >= (int)$lastDay) {
            return $lastDay - $today;
        }
        if ((int)$day >= (int)$today) {
            return $day - $today;
        }

        return $lastDay - $today + $day;
    }

    private function calcResetDayByYearFirstDay(): int
    {
        $nextYear = strtotime(date("Y-01-01", strtotime('+1 year')));
        return (int)(($nextYear - time()) / 86400);
    }

    private function calcResetDayByYearExpiredAt(int $expiredAt): int
    {
        $md = date('m-d', $expiredAt);
        $nowYear = strtotime(date("Y-{$md}"));
        $nextYear = strtotime('+1 year', $nowYear);
        if ($nowYear > time()) {
            return (int)(($nowYear - time()) / 86400);
        }
        return (int)(($nextYear - time()) / 86400);
    }

    public function getResetDay(User $user)
    {
        if (!isset($user->plan)) {
            if ($user->plan_id === NULL) return null;
            $user->plan = Plan::find($user->plan_id);
        }
        if ($user->expired_at <= time() || $user->expired_at === NULL) return null;
        // if reset method is not reset
        if ($user->plan->reset_traffic_method === 2) return null;
        switch (true) {
            case ($user->plan->reset_traffic_method === NULL): {
                $resetTrafficMethod = config('v2board.reset_traffic_method', 0);
                switch ((int)$resetTrafficMethod) {
                    // month first day
                    case 0:
                        return $this->calcResetDayByMonthFirstDay();
                    // expire day
                    case 1:
                        return $this->calcResetDayByExpireDay($user->expired_at);
                    // no action
                    case 2:
                        return null;
                    // year first day
                    case 3:
                        return $this->calcResetDayByYearFirstDay();
                    // year expire day
                    case 4:
                        return $this->calcResetDayByYearExpiredAt($user->expired_at);
                }
                break;
            }
            case ($user->plan->reset_traffic_method === 0): {
                return $this->calcResetDayByMonthFirstDay();
            }
            case ($user->plan->reset_traffic_method === 1): {
                return $this->calcResetDayByExpireDay($user->expired_at);
            }
            case ($user->plan->reset_traffic_method === 2): {
                return null;
            }
            case ($user->plan->reset_traffic_method === 3): {
                return $this->calcResetDayByYearFirstDay();
            }
            case ($user->plan->reset_traffic_method === 4): {
                return $this->calcResetDayByYearExpiredAt($user->expired_at);
            }
        }
        return null;
    }

    public function getResetPeriod(User $user)
    {
        if ($user->plan_id === NULL) return null;
        $plan = Plan::find($user->plan_id);
        if ($user->expired_at <= time() || $user->expired_at === NULL) return null;
        // if reset method is not reset
        if ($plan->reset_traffic_method === 2) return null;
        switch (true) {
            case ($plan->reset_traffic_method === NULL) : {
                $resetTrafficMethod = config('v2board.reset_traffic_method', 0);
                switch ((int)$resetTrafficMethod) {
                    case 0:
                        return 1;
                    case 1:
                        return 30;
                    case 2:
                        return null;
                    case 3:
                        return 12;
                    case 4:
                        return 365;
                }
                break;
            }
            case ($plan->reset_traffic_method === 0): {
                return 1;
            }
            case ($plan->reset_traffic_method === 1): {
                return 30;
            }
            case ($plan->reset_traffic_method === 2): {
                return null;
            }
            case ($plan->reset_traffic_method === 3): {
                return 12;
            }
            case ($plan->reset_traffic_method === 4): {
                return 365;
            }
        }
        return null;
    }

    public function isAvailable(User $user)
    {
        if (!$user->banned && $user->transfer_enable && ($user->expired_at > time() || $user->expired_at === NULL)) {
            return true;
        }
        return false;
    }

    /**
     * 根据验证状态、注册时间和订阅购买记录判断用户类型。
     */
    public function getUserType(User $user): string
    {
        if ((int)$user->verification_status !== 2) {
            return self::USER_TYPE_NEW;
        }
        if ((int)$user->created_at > strtotime('-3 months')) {
            return self::USER_TYPE_NEW;
        }

        return $this->hasPurchasedSubscription($user) ? self::USER_TYPE_OLD : self::USER_TYPE_NEW;
    }

    /**
     * 判断用户是否存在已完成或已折抵的订阅购买记录。
     */
    protected function hasPurchasedSubscription(User $user): bool
    {
        return Order::where('user_id', $user->id)
            ->where('plan_id', '>', 0)
            ->whereNotIn('period', ['deposit', 'reset_price'])
            ->whereIn('status', [3, 4])
            ->exists();
    }

    public function getAvailableUsers()
    {
        return User::whereRaw('u + d < transfer_enable')
            ->where(function ($query) {
                $query->where('expired_at', '>=', time())
                ->orWhereNull('expired_at');
            })
            ->where('banned', 0)
            ->get();
    }

    public function getDeviceLimitedUsers()
    {
        return User::whereRaw('u + d < transfer_enable')
            ->where(function ($query) {
                $query->where('expired_at', '>=', time())
                ->orWhereNull('expired_at');
            })
            ->where('banned', 0)
            ->where('device_limit','>', 0)
            ->select('id')
            ->get();
    }

    public function getUnAvailbaleUsers()
    {
        return User::where(function ($query) {
            $query->where('expired_at', '<', time())
                ->orWhere('expired_at', 0);
        })
            ->where(function ($query) {
            $query->where('plan_id', NULL)
                ->orWhere('transfer_enable', 0);
        })
            ->get();
    }

    public function getUsersByIds($ids)
    {
        return User::whereIn('id', $ids)->get();
    }

    public function getAllUsers()
    {
        return User::all();
    }

    public function addBalance(int $userId, int $balance):bool
    {
        $user = User::lockForUpdate()->find($userId);
        if (!$user) {
            return false;
        }
        $user->balance = $user->balance + $balance;
        if ($user->balance < 0) {
            return false;
        }
        if (!$user->save()) {
            return false;
        }
        return true;
    }

    public function isNotCompleteOrderByUserId(int $userId): bool
    {
        return Order::where('user_id', $userId)
            ->whereIn('status', [0, 1])
            ->exists();
    }

    public function trafficFetch(array $server, string $protocol, array $data)
    {
        TrafficFetchJob::dispatch($data, $server, $protocol);
        StatUserJob::dispatch($data, $server, $protocol, 'd');
        StatServerJob::dispatch($data, $server, $protocol, 'd');
    }

    public static function getMaxId()
    {
        return User::max('id');
    }
}
