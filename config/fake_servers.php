<?php

return [
    // 验证状态为红色或深色的用户仅接收这些虚假节点。
    'count' => 10,
    // 例如填写 cc.domain.ltd，生成的完整域名为 8e579f.cc.domain.ltd。
    'host_suffix' => 'do.com',
    // 多个节点名称后缀使用英文逗号分隔；只填一个时全部节点使用该后缀，留空时不追加。例如填 DIRECT,BGP 等等
    'name_suffix' => '',
    'port_min' => 10000,
    'port_max' => 60000,
];
