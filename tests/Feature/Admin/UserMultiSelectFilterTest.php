<?php

namespace Tests\Feature\Admin;

use App\Http\Controllers\V1\Admin\UserController;
use App\Models\User;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\TestCase;

class UserMultiSelectFilterTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config([
            'database.default' => 'sqlite',
            'database.connections.sqlite' => [
                'driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '',
                'foreign_key_constraints' => false,
            ],
        ]);
        DB::purge('sqlite');
        DB::reconnect('sqlite');
        Schema::create('v2_user', function (Blueprint $table): void {
            $table->increments('id');
            $table->integer('verification_status');
            $table->integer('group_id')->nullable();
        });
        DB::table('v2_user')->insert([
            ['id' => 1, 'verification_status' => 0, 'group_id' => 1],
            ['id' => 2, 'verification_status' => 1, 'group_id' => 2],
            ['id' => 3, 'verification_status' => 2, 'group_id' => 1],
            ['id' => 4, 'verification_status' => 4, 'group_id' => 3],
            ['id' => 5, 'verification_status' => 0, 'group_id' => null],
        ]);
    }

    protected function tearDown(): void
    {
        DB::disconnect('sqlite');
        parent::tearDown();
    }

    /** @dataProvider matchingFilters */
    public function testFiltersReturnMatchingUsers(array $filters, array $expected): void
    {
        $query = User::query()->orderBy('id');
        $this->applyFilters($query, $filters);
        $this->assertSame($expected, $query->pluck('id')->all());
    }

    public function matchingFilters(): array
    {
        return [
            'multiple statuses including zero' => [[['key' => 'verification_status', 'condition' => '=', 'value' => [0, 2]]], [1, 3, 5]],
            'multiple groups' => [[['key' => 'group_id', 'condition' => '=', 'value' => [1, 3]]], [1, 3, 4]],
            'combined selections use AND' => [[
                ['key' => 'verification_status', 'condition' => '=', 'value' => ['0', '4']],
                ['key' => 'group_id', 'condition' => '=', 'value' => ['1', '2']],
            ], [1]],
            'legacy scalar zero' => [[['key' => 'verification_status', 'condition' => '=', 'value' => 0]], [1, 5]],
            'legacy scalar group' => [[['key' => 'group_id', 'condition' => '=', 'value' => 2]], [2]],
            'exclude selected statuses' => [[['key' => 'verification_status', 'condition' => '!=', 'value' => [0, 2]]], [2, 4]],
            'no matching group' => [[['key' => 'group_id', 'condition' => '=', 'value' => [99]]], []],
        ];
    }

    /** @dataProvider invalidFilters */
    public function testInvalidArrayFiltersAreRejected(array $filter): void
    {
        try {
            $this->applyFilters(User::query(), [$filter]);
            $this->fail('Expected invalid array filter to be rejected');
        } catch (ValidationException $e) {
            $this->assertNotEmpty($e->errors());
        } catch (HttpException $e) {
            $this->assertSame(422, $e->getStatusCode());
        }
    }

    public function invalidFilters(): array
    {
        return [
            'empty selection' => [['key' => 'group_id', 'condition' => '=', 'value' => []]],
            'unknown status' => [['key' => 'verification_status', 'condition' => '=', 'value' => [5]]],
            'non-integer group' => [['key' => 'group_id', 'condition' => '=', 'value' => ['invalid']]],
            'nested selection' => [['key' => 'group_id', 'condition' => '=', 'value' => [[1]]]],
            'wrong field' => [['key' => 'email', 'condition' => '=', 'value' => ['a@example.test']]],
            'wrong comparison' => [['key' => 'group_id', 'condition' => '>', 'value' => [1, 2]]],
        ];
    }

    private function applyFilters($query, array $filters): void
    {
        $method = new \ReflectionMethod(UserController::class, 'filter');
        $method->setAccessible(true);
        $method->invoke(new UserController(), new Request(['filter' => $filters]), $query);
    }
}
