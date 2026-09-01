<?php

namespace Tests\Feature\Admin;

use App\Http\Middleware\Admin;
use App\Http\Middleware\RequestLog;
use App\Models\ServerV2node;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class V2nodeShadowTlsTransitionTest extends TestCase
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
        $this->createServerTable();
        $this->withoutMiddleware([Admin::class, RequestLog::class]);
    }

    protected function tearDown(): void
    {
        DB::disconnect('sqlite');
        parent::tearDown();
    }

    public function testSwitchingFromShadowTlsToHysteria2RemovesShadowTlsSettings(): void
    {
        $server = ServerV2node::create($this->serverAttributes([
            'protocol' => 'shadowsocks',
            'tls' => 3,
            'tls_settings' => [
                'server_name' => 'hy2.example.test',
                'cert_mode' => 'file',
                'cert_file' => '/etc/certs/server.crt',
                'key_file' => '/etc/certs/server.key',
                'plugin' => 'shadow-tls',
                'shadow_tls' => 'fallback.example.test',
                'shadow_tls_version' => '2',
                'shadow_tls_password' => 'shadow-secret',
                'wildcard_sni' => 'off',
            ],
        ]));

        $securePath = config(
            'v2board.secure_path',
            config('v2board.frontend_admin_path', hash('crc32b', config('app.key')))
        );
        $response = $this->postJson("/api/v1/{$securePath}/server/v2node/save", array_merge(
            $this->serverAttributes(),
            [
                'id' => $server->id,
                'protocol' => 'hysteria2',
                'tls' => 3,
                'tls_settings' => $server->tls_settings,
            ]
        ));

        $response->assertOk();
        $server->refresh();
        $this->assertSame(1, (int)$server->tls);
        $this->assertSame([
            'server_name' => 'hy2.example.test',
            'cert_mode' => 'file',
            'cert_file' => '/etc/certs/server.crt',
            'key_file' => '/etc/certs/server.key',
        ], $server->tls_settings);
    }

    private function serverAttributes(array $overrides = []): array
    {
        return array_merge([
            'group_id' => [1],
            'route_id' => [],
            'name' => 'ShadowTLS transition test',
            'host' => '127.0.0.1',
            'listen_ip' => '0.0.0.0',
            'port' => '443',
            'server_port' => 443,
            'rate' => '1',
            'show' => 1,
            'protocol' => 'hysteria2',
            'tls' => 1,
            'tls_settings' => [],
            'network' => 'tcp',
            'disable_sni' => 0,
            'zero_rtt_handshake' => 0,
            'up_mbps' => 100,
            'down_mbps' => 100,
        ], $overrides);
    }

    private function createServerTable(): void
    {
        Schema::create('v2_server_v2node', function (Blueprint $table): void {
            $table->increments('id');
            $table->text('group_id');
            $table->text('route_id')->nullable();
            $table->string('name');
            $table->unsignedInteger('parent_id')->nullable();
            $table->string('host');
            $table->string('listen_ip')->default('0.0.0.0');
            $table->string('port');
            $table->unsignedInteger('server_port');
            $table->text('tags')->nullable();
            $table->string('rate');
            $table->boolean('show')->default(false);
            $table->unsignedInteger('sort')->nullable();
            $table->string('protocol');
            $table->unsignedTinyInteger('tls');
            $table->text('tls_settings')->nullable();
            $table->string('flow')->nullable();
            $table->string('network');
            $table->text('network_settings')->nullable();
            $table->text('trusted_x_forwarded_for')->nullable();
            $table->string('encryption')->nullable();
            $table->text('encryption_settings')->nullable();
            $table->boolean('disable_sni')->default(false);
            $table->string('udp_relay_mode')->nullable();
            $table->boolean('zero_rtt_handshake')->default(false);
            $table->string('congestion_control')->nullable();
            $table->string('cipher')->nullable();
            $table->unsignedInteger('up_mbps')->default(0);
            $table->unsignedInteger('down_mbps')->default(0);
            $table->string('obfs')->nullable();
            $table->string('obfs_password')->nullable();
            $table->text('padding_scheme')->nullable();
            $table->unsignedBigInteger('created_at');
            $table->unsignedBigInteger('updated_at');
        });
    }
}
