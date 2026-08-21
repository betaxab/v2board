<?php

namespace Tests\Feature\Passport;

use App\Models\User;
use App\Services\ServerService;
use App\Utils\CacheKey;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class ServerRiskRestrictionTest extends TestCase
{
    private const MATCHED_IP = '203.0.113.10';
    private const PASSWORD = 'phase3-password';
    private const GROUP_ID = 7;

    /**
     * 建立服务器限制测试所需的 SQLite 表和确定性配置。
     */
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'app.key' => str_repeat('phase3-server-risk-key-', 4),
            'cache.default' => 'array',
            'database.default' => 'sqlite',
            'database.connections.sqlite' => [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
                'foreign_key_constraints' => false,
            ],
            'v2board.password_limit_enable' => 0,
            'v2board.ip_risk_blacklist_enable' => 1,
            'v2board.ip_risk_exception_rules' => '',
            'fake_servers.count' => 4,
            'fake_servers.host_suffix' => 'risk.example.test',
            'fake_servers.name_suffix' => '[DIRECT],[BGP]',
            'fake_servers.port_min' => 12000,
            'fake_servers.port_max' => 12010,
        ]);
        DB::purge('sqlite');
        DB::reconnect('sqlite');
        Cache::flush();
        $this->createTables();
        $this->installSnapshot([self::MATCHED_IP]);
    }

    /**
     * 关闭 SQLite 连接以隔离后续测试。
     */
    protected function tearDown(): void
    {
        DB::disconnect('sqlite');
        parent::tearDown();
    }

    /**
     * 验证红色和深色用户只获得稳定且唯一的虚假节点。
     *
     * @dataProvider restrictedStatusProvider
     */
    public function testRestrictedUsersReceiveOnlyStableFakeServers(int $status): void
    {
        $user = $this->createUser(['verification_status' => $status]);
        $service = new ServerService();

        $first = $service->getAvailableServers($user);
        $second = $service->getAvailableServers($user);

        $this->assertCount(4, $first);
        $this->assertSame(
            array_column($first, 'name'),
            array_column($second, 'name')
        );
        $this->assertSame(
            array_column($first, 'host'),
            array_column($second, 'host')
        );
        $this->assertSame(
            array_column($first, 'port'),
            array_column($second, 'port')
        );
        $this->assertCount(4, array_unique(array_column($first, 'name')));

        foreach ($first as $server) {
            $this->assertSame('shadowsocks', $server['type']);
            $this->assertSame('2022-blake3-aes-128-gcm', $server['cipher']);
            $this->assertMatchesRegularExpression('/^[a-f0-9]{6}\.risk\.example\.test$/', $server['host']);
            $this->assertMatchesRegularExpression('/^(HK|US|JP|TW|SG|GB|DE)-[A-Z]-\d+ \[(DIRECT|BGP)\]$/', $server['name']);
            $this->assertGreaterThanOrEqual(12000, $server['port']);
            $this->assertLessThanOrEqual(12010, $server['port']);
        }
    }

    /**
     * 提供红色和深色受限状态。
     */
    public function restrictedStatusProvider(): array
    {
        return [
            'red' => [3],
            'dark' => [4],
        ];
    }

    /**
     * 验证后端可加载用户查询排除红色和深色用户。
     */
    public function testBackendUserLoadingExcludesRedAndDarkStatuses(): void
    {
        $grey = $this->createUser(['verification_status' => 0]);
        $green = $this->createUser(['verification_status' => 2]);
        $this->createUser(['verification_status' => 3]);
        $this->createUser(['verification_status' => 4]);

        $users = (new ServerService())->getAvailableUsers([self::GROUP_ID]);

        $this->assertSame([$grey->id, $green->id], $users->pluck('id')->all());
    }

    /**
     * 验证真实命中登录后立即触发两项服务器限制。
     */
    public function testMatchedLoginImmediatelyAppliesServerRestrictions(): void
    {
        $user = $this->createUser(['verification_status' => 2]);

        $response = $this->withServerVariables(['REMOTE_ADDR' => self::MATCHED_IP])
            ->postJson('/api/v1/passport/auth/login', [
                'email' => $user->email,
                'password' => self::PASSWORD,
            ]);

        $response->assertOk();
        $user->refresh();
        $this->assertSame(3, (int)$user->verification_status);
        $service = new ServerService();
        $servers = $service->getAvailableServers($user);
        $this->assertCount(4, $servers);
        $this->assertSame(
            ['shadowsocks'],
            array_values(array_unique(array_column($servers, 'type')))
        );
        $this->assertFalse($service->getAvailableUsers([self::GROUP_ID])->contains('id', $user->id));
    }

    /**
     * 创建用户和认证日志的最小数据表。
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
     * 创建满足服务器加载条件的认证用户。
     */
    private function createUser(array $attributes = []): User
    {
        $sequence = User::count() + 1;
        $user = new User();
        $user->forceFill(array_merge([
            'email' => "server-user{$sequence}@example.test",
            'password' => password_hash(self::PASSWORD, PASSWORD_DEFAULT),
            'password_algo' => null,
            'password_salt' => null,
            'uuid' => sprintf('10000000-0000-4000-8000-%012d', $sequence),
            'token' => md5("phase3-server-user-{$sequence}"),
            'verification_status' => 0,
            'banned' => 0,
            'is_admin' => 0,
            'is_staff' => 0,
            'group_id' => self::GROUP_ID,
            'u' => 100,
            'd' => 100,
            'transfer_enable' => 1000,
            'expired_at' => time() + 3600,
        ], $attributes));
        $user->save();

        return $user;
    }
}
