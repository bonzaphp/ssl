
## OpenSsl

## 安装

```php
composer require bonza/ssl
```

### 1. 使用示例

```php

$config = [
    'digest_alg'       => 'sha512',
    'private_key_bits' => 4096,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
];

$ssl = new OpenSsl($config);



==暂时没有测试覆盖==

```

