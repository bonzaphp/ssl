<?php
/**
 * Created by yang
 * User: bonzaphp@gmail.com
 * Date: 2020-05-29
 * Time: 09:28
 */

/**
 * Created by yang
 * User: bonzaphp@gmail.com
 * Date: 2019-10-30
 * Time: 11:33
 */

namespace bonza\ssl;

use bonza\ssl\exception\RuntimeException;
use Exception;

class OpenSsl
{
    /**
     * 私钥对象
     * @var resource
     */
    private $privateKey;

    /**
     * $config = [
     *     'digest_alg'       => 'sha512',
     *     'private_key_bits' => 4096,
     *     'private_key_type' => OPENSSL_KEYTYPE_RSA,
     * ];
     * OpenSsl constructor.
     * @param  array  $config
     */
    public function __construct(array $config)
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('openssl not load');
        }
        // 生成私钥对象
        $this->privateKey = openssl_pkey_new($config);
    }

    /**
     * 生成私钥
     * @author bonzaphp@gmail.com
     */
    private function generatePrivateKey()
    {
        $res = openssl_pkey_export($this->privateKey, $out);
        if (false === $res) {
            throw new RuntimeException('生成私钥失败');
        }
        return $out;
    }

    /**
     * 生成公钥
     * @return mixed
     * @author bonzaphp@gmail.com
     */
    private function generatePublicKey()
    {
        $detail = openssl_pkey_get_details($this->privateKey);
        if (false === $detail) {
            throw new RuntimeException('获取公钥失败');
        }
        return $detail['key'];
    }

    /**
     * 保存秘钥到文件
     * @param  string  $dir  目录地址
     * @param  string  $file_name  文件名称
     * @author bonzaphp@gmail.com
     */
    public function generateKey(string $dir = '', string $file_name = 'id_rsa'): void
    {
        if ('' === $dir) {
            $dir = realpath('.');
        }
        if (!is_dir($dir) || !is_writable($dir)) {
            throw new RuntimeException($dir.'目录无法写入');
        }
        $handle = fopen($dir.$file_name.'.log', 'wb+');
        if (false === $handle) {
            throw new RuntimeException($dir.'写入文件错误');
        }
        fclose($handle);
        rtrim($dir, DIRECTORY_SEPARATOR);
        if (!file_exists($dir.DIRECTORY_SEPARATOR.$file_name)) {
            file_put_contents($dir.DIRECTORY_SEPARATOR.$file_name, $this->generatePrivateKey());
        }
        if (!file_exists($dir.DIRECTORY_SEPARATOR.$file_name.'.pub')) {
            file_put_contents($dir.DIRECTORY_SEPARATOR.$file_name.'.pub', $this->generatePublicKey());
        }
    }

    /**
     * 获取可用的私钥内容
     * @param  string  $private_key  私钥PEM格式
     * @return resource
     * @author bonzaphp@gmail.com
     */
    public function getPrivateKey(string $private_key)
    {
        $privateKey = openssl_pkey_get_private($private_key);
        if (false === $privateKey) {
            throw new RuntimeException('获取私钥失败');
        }
        return $privateKey;
    }

    /**
     * 获取可用的公钥内容
     * @param  string  $public_key  公钥PEM格式
     * @return resource
     * @author bonzaphp@gmail.com
     */
    public function getPublicKey(string $public_key)
    {
        $publicKey = openssl_pkey_get_public($public_key);
        if (false === $publicKey) {
            throw new RuntimeException('获取公钥失败');
        }
        return $publicKey;
    }

    /**
     * 解密公钥加密的字符串
     * @param  string  $private_key  私钥字符串
     * @param  string  $encrypted_key  要解密的字符串
     * @param  $split_len
     * @return string
     * @author bonzaphp@gmail.com
     */
    public function decodeByPrivateKey(string $private_key, string $encrypted_key, $split_len = 128): string
    {
        $privateKey = openssl_pkey_get_private($private_key);
        $encrypted_key_source = base64_decode($encrypted_key);
        $encrypted_str = str_split($encrypted_key_source, $split_len);
        $decrypted = '';
        foreach ($encrypted_str as $val) {
            $decrypted_temp = '';
            $res = openssl_private_decrypt($val, $decrypted_temp, $privateKey, OPENSSL_PKCS1_PADDING);
            if (false === $res) {
                throw new RuntimeException('解密失败');
            }
            $decrypted .= $decrypted_temp;
        }
        return $decrypted;
    }

    /**
     * 解密公钥加密的字符串
     * @param  string  $public_key_str  公钥字符串
     * @param  string  $encrypted_key  要解密的字符串
     * @return string
     * @author bonzaphp@gmail.com
     */
    public function decodeByPublicKey(string $public_key_str, string $encrypted_key): string
    {
        $public_key = openssl_pkey_get_public($public_key_str);
        $res = openssl_public_decrypt($encrypted_key, $decrypted, $public_key);
        if (false === $res) {
            throw new RuntimeException('解密失败');
        }
        return $decrypted;
    }

    /**
     * 使用公钥加密字符串
     * @param  string  $public_key  公钥字符串
     * @param  string  $str  要加密的字符串
     * @return string
     * @author bonzaphp@gmail.com
     */
    public function encodeByPublicKey(string $public_key, string $str): string
    {
        $publicKey = openssl_pkey_get_public($public_key);
        $key_len = openssl_pkey_get_details($publicKey)['bits'];
        $encrypted_str = str_split($str, $key_len / 8 - 11);
        $encrypted = '';
        foreach ($encrypted_str as $val) {
            $encrypted_temp = '';
            $res = openssl_public_encrypt($val, $encrypted_temp, $publicKey, OPENSSL_PKCS1_PADDING);
            if (false === $res) {
                throw new RuntimeException('加密失败');
            }
            $encrypted .= $encrypted_temp;
        }
        return base64_encode($encrypted);
    }

    /**
     * 使用私钥加密字符串
     * @param  string  $private_key_str  私钥字符串
     * @param  string  $str  要加密的字符串
     * @return string
     * @author bonzaphp@gmail.com
     */
    public function encodeByPrivateKey(string $private_key_str, string $str): string
    {
        $private_key = openssl_pkey_get_private($private_key_str);
        $res = openssl_private_encrypt($str, $encrypted, $private_key);
        if (false === $res) {
            throw new RuntimeException('加密失败');
        }
        return $encrypted;
    }

    /**
     * 对称加密
     * @param  string  $data  要加密的数据
     * @param  string  $key  加密秘钥
     * @param  string  $encryptMethod  加密算法
     * @return array
     * @author bonzaphp@gmail.com
     */
    public function encode(string $data, string $key, string $encryptMethod = 'aes-256-cbc'): array
    {
        try {
            // 生成IV
            $ivLength = openssl_cipher_iv_length($encryptMethod);
            $iv = random_bytes($ivLength);// 加密
            $encrypt_str = openssl_encrypt($data, $encryptMethod, $key, 0, $iv);
            return [
                'encrypt_str' => $encrypt_str,
                'iv'          => $iv
            ];
        } catch (Exception $e) {
            throw new RuntimeException($e->getMessage());
        }
    }

    /**
     * 对称解密
     * @param  string  $encrypted  要解密字符
     * @param  string  $key  加密秘钥
     * @param  string  $iv
     * @param  string  $encryptMethod  加密方法
     * @return string
     * @author bonzaphp@gmail.com
     */
    public function decode(string $encrypted, string $key, string $iv, string $encryptMethod = 'aes-256-cbc'): string
    {
        // 解密
        return openssl_decrypt($encrypted, $encryptMethod, $key, 0, $iv);
    }

    /**
     * base64 url编码
     * @param $input
     * @return string
     */
    protected static function base64url_encode(string $input): string
    {
        return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
    }

    /**
     * base64解码URL传过来的数据
     * @param $input
     * @return string
     */
    protected static function base64url_decode(string $input): string
    {
        return base64_decode(strtr($input, '-_', '+/').str_repeat('=', 3 - (3 + strlen($input)) % 4));
    }

}