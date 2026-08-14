<?php

namespace App\Services;

use App\Models\User;
use InvalidArgumentException;

class FakeServerService
{
    private const MAX_SERVER_COUNT = 1000;
    private const CIPHER = '2022-blake3-aes-128-gcm';
    private const COUNTRY_CODES = ['HK', 'US', 'JP', 'TW', 'SG', 'GB', 'DE'];
    private const NAME_LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /**
     * 为指定用户生成稳定的虚假 Shadowsocks 节点。
     */
    public function generate(User $user): array
    {
        $count = (int)config('fake_servers.count', 10);
        if ($count < 0 || $count > self::MAX_SERVER_COUNT) {
            throw new InvalidArgumentException('Fake server count must be between 0 and 1000.');
        }
        if ($count === 0) {
            return [];
        }

        $hostSuffix = $this->normalizeHostSuffix(config('fake_servers.host_suffix', 'invalid'));
        $nameSuffixes = $this->parseNameSuffixes(config('fake_servers.name_suffix', '[DIRECT],[BGP]'));
        $portMin = (int)config('fake_servers.port_min', 10000);
        $portMax = (int)config('fake_servers.port_max', 60000);
        $this->validatePortRange($portMin, $portMax);

        $seed = implode(':', [
            $user->id,
            $user->uuid,
            (int)$user->verification_status,
        ]);
        $portCount = $portMax - $portMin + 1;
        $createdAt = 1600000000 + (hexdec(substr(hash('sha256', $hostSuffix), 0, 7)) % 300000000);
        $servers = [];

        for ($index = 0; $index < $count; $index++) {
            $digest = hash('sha256', $seed . ':' . $index);
            $hostPrefix = substr(sha1($seed . ':' . $index), 0, 6);
            $port = $portMin + (hexdec(substr($digest, 0, 8)) % $portCount);
            $servers[] = [
                'id' => -($index + 1),
                'type' => 'shadowsocks',
                'group_id' => [],
                'route_id' => [],
                'parent_id' => null,
                'tags' => [],
                'name' => $this->buildNodeName($index, $nameSuffixes),
                'rate' => 1,
                'host' => $hostPrefix . '.' . $hostSuffix,
                'port' => (string)$port,
                'server_port' => $port,
                'cipher' => self::CIPHER,
                'obfs' => null,
                'obfs_settings' => [],
                'network' => 'tcp',
                'network_settings' => [],
                'tls' => 0,
                'tls_settings' => [],
                'show' => 1,
                'sort' => $index + 1,
                'created_at' => $createdAt,
                'updated_at' => $createdAt,
                'last_check_at' => time(),
            ];
        }

        return $servers;
    }

    /**
     * 按地区、字母和轮次生成不重复的虚假节点名称，并追加自定义后缀。
     */
    private function buildNodeName(int $index, array $nameSuffixes): string
    {
        $countryCount = count(self::COUNTRY_CODES);
        $combinationCount = $countryCount * strlen(self::NAME_LETTERS);
        $combinationIndex = $index % $combinationCount;
        $country = self::COUNTRY_CODES[$combinationIndex % $countryCount];
        $letter = self::NAME_LETTERS[intdiv($combinationIndex, $countryCount)];
        $number = intdiv($index, $combinationCount) + 1;

        $name = sprintf('%s-%s-%d', $country, $letter, $number);
        if (!$nameSuffixes) {
            return $name;
        }

        $nameSuffix = $nameSuffixes[$index % count($nameSuffixes)];

        return $name . ' ' . $nameSuffix;
    }

    /**
     * 解析逗号分隔的节点名称后缀列表并移除空项。
     */
    private function parseNameSuffixes($nameSuffixes): array
    {
        $suffixes = array_map('trim', explode(',', (string)$nameSuffixes));

        return array_values(array_filter($suffixes, function ($suffix) {
            return $suffix !== '';
        }));
    }

    /**
     * 规范化并校验虚假节点的域名后缀。
     */
    private function normalizeHostSuffix($hostSuffix): string
    {
        $hostSuffix = strtolower(trim((string)$hostSuffix));
        $hostSuffix = trim($hostSuffix, '.');
        $valid = preg_match(
            '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/',
            $hostSuffix
        );
        if ($valid !== 1) {
            throw new InvalidArgumentException('Fake server host suffix is invalid.');
        }
        return $hostSuffix;
    }

    /**
     * 校验虚假节点端口范围是否合法。
     */
    private function validatePortRange(int $portMin, int $portMax): void
    {
        if ($portMin < 1 || $portMax > 65535 || $portMin > $portMax) {
            throw new InvalidArgumentException('Fake server port range is invalid.');
        }
    }
}
