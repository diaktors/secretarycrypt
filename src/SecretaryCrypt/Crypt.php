<?php
/**
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * PHP Version 5
 *
 * @category Service
 * @package  SecretaryCrypt
 * @author   Michael Scholl <michael@wesrc.com>
 * @license  http://www.opensource.org/licenses/mit-license.html MIT License
 * @link     https://github.com/wesrc/secretarycrypt
 */

namespace SecretaryCrypt;

/**
 * Crypt Service
 *
 * @category Service
 * @package  SecretaryCrypt
 * @author   Michael Scholl <michael@wesrc.com>
 * @license  http://www.opensource.org/licenses/mit-license.html MIT License
 * @link     https://github.com/wesrc/secretarycrypt
 */
class Crypt
{
    /**
     * Create a private key and sign it with passphrase
     *
     * @param  string $passphrase
     * @return array
     * @throws \InvalidArgumentException If passphrase is empty
     */
    public function createPrivateKey($passphrase)
    {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException('Passphrase cannot be empty');
        }
        $keyConfig = array('private_key_bits' => 2048);
        $keyRes    = openssl_pkey_new($keyConfig);
        $pubKey    = openssl_pkey_get_details($keyRes);
        openssl_pkey_export($keyRes, $privKey, $passphrase);
        openssl_free_key($keyRes);
        return array(
            'pub'  => $pubKey['key'],
            'priv' => $privKey
        );
    }

    /**
     * Encrypt string with multiple public keys
     *
     * @param  string $content
     * @param  array  $keys
     * @return array
     * @throws \InvalidArgumentException If key is empty
     * @throws \LogicException           If key is not readable as key
     * @throws \LogicException           If encryption errors
     */
    public function encryptForMultipleKeys($content, array $keys)
    {
        if (empty($keys)) {
            throw new \InvalidArgumentException('Keys array canot be empty');
        }
        $pubKeys = array();
        foreach ($keys as $userId => $key) {
            $pk = openssl_pkey_get_public($key);
            if (false === $pk) {
                throw new \LogicException('Key is not readable');
            }
            $pubKey    = openssl_pkey_get_details($pk);
            $pubKeys[] = $pubKey['key'];
            openssl_free_key($pk);
            unset($pubKey);
        }
        $sealCheck = openssl_seal(serialize($content), $sealedContent, $eKeys, $pubKeys);
        unset($pubKeys);
        if (false === $sealCheck) {
            throw new \LogicException('An error occurred while encrypting');
        }
        $eKeysEncoded = array();
        foreach ($eKeys as $eKey) {
            $eKeysEncoded[] = base64_encode($eKey);
        }
        return array(
            'ekeys'   => $eKeysEncoded,
            'content' => base64_encode($sealedContent)
        );
    }

    /**
     * Encrypt string with public key
     *
     * @param  string $content
     * @param  string $key
     * @return array
     * @throws \InvalidArgumentException If key is empty
     * @throws \LogicException           If key is not readable as key
     * @throws \LogicException           If encryption errors
     */
    public function encryptForSingleKey($content, $key)
    {
        if (empty($key)) {
            throw new \InvalidArgumentException('Key canot be empty');
        }
        $pk = openssl_pkey_get_public($key);
        if (false === $pk) {
            throw new \LogicException('Key is not readable');
        }
        $pubKey    = openssl_pkey_get_details($pk);
        $sealCheck = openssl_seal(serialize($content), $sealedContent, $eKeys, array($pubKey['key']));
        openssl_free_key($pk);
        unset($pubKey);
        if (false === $sealCheck) {
            throw new \LogicException('An error occurred while encrypting');
        }
        return array(
            'ekey'    => base64_encode($eKeys[0]),
            'content' => base64_encode($sealedContent)
        );
    }

    /**
     * Decrypt string with private key, passphrase and eKey
     *
     * @param  string $content
     * @param  string $eKey
     * @param  string $key
     * @param  string $passphrase
     * @return string
     * @throws \InvalidArgumentException If content, ekey, key or passphrase is empty
     * @throws \LogicException           If key is not readable as key
     * @throws \LogicException           If encryption errors
     */
    public function decrypt($content, $eKey, $key, $passphrase)
    {
        if (empty($content)) {
            throw new \InvalidArgumentException('Content canot be empty');
        }
        if (empty($eKey)) {
            throw new \InvalidArgumentException('eKey canot be empty');
        }
        if (empty($key)) {
            throw new \InvalidArgumentException('Key canot be empty');
        }
        if (empty($passphrase)) {
            throw new \InvalidArgumentException('Passphrase canot be empty');
        }
        $pk = openssl_pkey_get_private($key, $passphrase);
        if (false === $pk) {
            throw new \LogicException('Key is not readable');
        }
        $content = base64_decode($content);
        $eKey    = base64_decode($eKey);
        $check   = openssl_open($content, $contentDecrypted, $eKey, $pk);
        openssl_free_key($pk);
        if (false === $check) {
            throw new \LogicException('An error occurred while decrypting');
        }
        return unserialize($contentDecrypted);
    }

    /**
     * Validate (private) key
     *
     * @param  string $key
     * @param  string $passphrase
     * @return true
     * @throws \InvalidArgumentException If key is empty
     * @throws \LogicException           If key is not readable as key
     */
    public function validateKey($key, $passphrase)
    {
        if (empty($key)) {
            throw new \InvalidArgumentException('Key canot be empty');
        }
        $pk = openssl_pkey_get_private($key, $passphrase);
        if (false === $pk) {
            throw new \LogicException('Key is not readable');
        }
        openssl_free_key($pk);
        return true;
    }

    /**
     * Validate (public) key
     *
     * @param  string $key
     * @return true
     * @throws \InvalidArgumentException If key is empty
     * @throws \LogicException           If key is not readable as key
     */
    public function validatePublicKey($key)
    {
        if (empty($key)) {
            throw new \InvalidArgumentException('Key canot be empty');
        }
        $pk = openssl_pkey_get_public($key);
        if (false === $pk) {
            throw new \LogicException('Key is not readable');
        }
        $check = openssl_pkey_get_details($pk);
        if ($check['bits'] != 2048) {
            throw new \LogicException('Provided key is not 2048 bit');
        }
        openssl_free_key($pk);
        return true;
    }
}
