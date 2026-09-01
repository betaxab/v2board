<?php

namespace Tests\Feature\User;

use App\Http\Middleware\User as UserMiddleware;
use App\Models\Order;
use App\Models\Plan;
use App\Models\User;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class OrderResetPackageTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'database.default' => 'sqlite',
            'database.connections.sqlite' => [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
                'foreign_key_constraints' => false,
            ],
        ]);
        DB::purge('sqlite');
        DB::reconnect('sqlite');
        $this->createTables();
        $this->withoutMiddleware(UserMiddleware::class);
    }

    protected function tearDown(): void
    {
        DB::disconnect('sqlite');
        parent::tearDown();
    }

    public function testNewUserCanBuyResetPackageForAssignedOldUserPlan(): void
    {
        $plan = $this->createOldUserPlan();
        $user = $this->createNewUserWithPlan($plan);

        $response = $this->postJson('/api/v1/user/order/save', [
            'user' => ['id' => $user->id],
            'plan_id' => $plan->id,
            'period' => 'reset_price',
        ]);

        $response->assertOk();
        $order = Order::firstOrFail();
        $this->assertSame($user->id, (int)$order->user_id);
        $this->assertSame($plan->id, (int)$order->plan_id);
        $this->assertSame('reset_price', $order->period);
        $this->assertSame(4, (int)$order->type);
        $this->assertSame(500, (int)$order->total_amount);
    }

    public function testNewUserCanRenewAssignedOldUserPlan(): void
    {
        $plan = $this->createOldUserPlan();
        $user = $this->createNewUserWithPlan($plan);

        $response = $this->postJson('/api/v1/user/order/save', [
            'user' => ['id' => $user->id],
            'plan_id' => $plan->id,
            'period' => 'month_price',
        ]);

        $response->assertOk();
        $order = Order::firstOrFail();
        $this->assertSame($user->id, (int)$order->user_id);
        $this->assertSame($plan->id, (int)$order->plan_id);
        $this->assertSame('month_price', $order->period);
        $this->assertSame(2, (int)$order->type);
    }

    public function testNewUserCanFetchAssignedOldUserPlanForRenewal(): void
    {
        $plan = $this->createOldUserPlan();
        $user = $this->createNewUserWithPlan($plan);

        $response = $this->getJson('/api/v1/user/plan/fetch?' . http_build_query([
            'user' => ['id' => $user->id],
            'id' => $plan->id,
        ]));

        $response->assertOk()
            ->assertJsonPath('data.id', $plan->id);
    }

    public function testAssignedOldUserPlanRemainsHiddenFromNewUserPlanList(): void
    {
        $plan = $this->createOldUserPlan();
        $user = $this->createNewUserWithPlan($plan);

        $response = $this->getJson('/api/v1/user/plan/fetch?' . http_build_query([
            'user' => ['id' => $user->id],
        ]));

        $response->assertOk()
            ->assertExactJson(['data' => []]);
    }

    public function testNewUserStillCannotBuyAnotherRestrictedPlan(): void
    {
        $assignedPlan = $this->createOldUserPlan();
        $restrictedPlan = $this->createOldUserPlan();
        $user = $this->createNewUserWithPlan($assignedPlan);

        $response = $this->postJson('/api/v1/user/order/save', [
            'user' => ['id' => $user->id],
            'plan_id' => $restrictedPlan->id,
            'period' => 'month_price',
        ]);

        $response->assertStatus(500)
            ->assertJsonFragment(['message' => __('This subscription is not available for your account')]);
        $this->assertSame(0, Order::count());
    }

    private function createOldUserPlan(): Plan
    {
        return Plan::create([
            'group_id' => 1,
            'transfer_enable' => 100,
            'name' => 'Assigned old-user plan',
            'show' => 1,
            'renew' => 1,
            'month_price' => 1000,
            'reset_price' => 500,
            'limit_user_types' => ['old'],
            'hide_on_mismatch' => 1,
        ]);
    }

    private function createNewUserWithPlan(Plan $plan): User
    {
        return User::create([
            'email' => 'new-user@example.test',
            'password' => 'unused',
            'balance' => 0,
            'u' => 1,
            'd' => 1,
            'transfer_enable' => 100,
            'banned' => 0,
            'is_admin' => 0,
            'is_staff' => 0,
            'uuid' => '00000000-0000-0000-0000-000000000001',
            'group_id' => $plan->group_id,
            'plan_id' => $plan->id,
            'verification_status' => 0,
            'token' => md5('new-user-reset-package'),
            'expired_at' => time() + 86400,
        ]);
    }

    private function createTables(): void
    {
        Schema::create('v2_plan', function (Blueprint $table): void {
            $table->increments('id');
            $table->unsignedInteger('group_id');
            $table->unsignedInteger('transfer_enable');
            $table->string('name');
            $table->boolean('show')->default(false);
            $table->boolean('renew')->default(true);
            $table->unsignedInteger('month_price')->nullable();
            $table->unsignedInteger('reset_price')->nullable();
            $table->unsignedInteger('capacity_limit')->nullable();
            $table->text('limit_user_types')->nullable();
            $table->boolean('hide_on_mismatch')->default(false);
            $table->unsignedBigInteger('created_at');
            $table->unsignedBigInteger('updated_at');
        });

        Schema::create('v2_user', function (Blueprint $table): void {
            $table->increments('id');
            $table->unsignedInteger('invite_user_id')->nullable();
            $table->string('email')->unique();
            $table->string('password');
            $table->integer('balance')->default(0);
            $table->unsignedInteger('discount')->nullable();
            $table->unsignedBigInteger('u')->default(0);
            $table->unsignedBigInteger('d')->default(0);
            $table->unsignedBigInteger('transfer_enable')->default(0);
            $table->boolean('banned')->default(false);
            $table->boolean('is_admin')->default(false);
            $table->boolean('is_staff')->default(false);
            $table->string('uuid');
            $table->unsignedInteger('group_id')->nullable();
            $table->unsignedInteger('plan_id')->nullable();
            $table->unsignedTinyInteger('verification_status')->default(0);
            $table->string('token')->unique();
            $table->unsignedBigInteger('expired_at')->nullable();
            $table->unsignedBigInteger('created_at');
            $table->unsignedBigInteger('updated_at');
        });

        Schema::create('v2_order', function (Blueprint $table): void {
            $table->increments('id');
            $table->unsignedInteger('invite_user_id')->nullable();
            $table->unsignedInteger('user_id');
            $table->unsignedInteger('plan_id');
            $table->unsignedInteger('type');
            $table->string('period');
            $table->string('trade_no')->unique();
            $table->integer('total_amount');
            $table->integer('status')->default(0);
            $table->unsignedBigInteger('created_at');
            $table->unsignedBigInteger('updated_at');
        });
    }
}
