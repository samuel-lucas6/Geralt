using System;
using System.Runtime.InteropServices;

/*
    Geralt: A cryptographic library for .NET based on libsodium.
    Copyright (c) 2021 Samuel Lucas
    Copyright (c) 2017-2020 tabrath
    Copyright (c) 2013-2017 Adam Caudill & Contributors

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
    COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

namespace Geralt
{
    /// <summary>libsodium library binding.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/internals </remarks>
    internal static partial class LibsodiumLibrary
    {
#if IOS
        const string DllName = "__Internal";
#else
        private const string _dllName = "libsodium";
        private const CallingConvention _callingConvention = CallingConvention.Cdecl;
#endif

        // sodium_init
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern void sodium_init();

        // sodium_version_string
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern IntPtr sodium_version_string();

        // randombytes_buf
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern void randombytes_buf(byte[] randomBytes, int count);

        // randombytes_uniform
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int randombytes_uniform(int upperBound);

        // sodium_compare
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int sodium_compare(byte[] a, byte[] b, long length);

        // sodium_increment
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern void sodium_increment(byte[] array, long arrayLength);

        // sodium_add
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern void sodium_add(byte[] a, byte[] b, long arrayLength);

        // sodium_sub
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern void sodium_sub(byte[] a, byte[] b, long arrayLength);

        // crypto_hash
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_hash(byte[] hash, byte[] message, long messageLength);

        // crypto_hash_sha512
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_hash_sha512(byte[] hash, byte[] message, long messageLength);

        // crypto_hash_sha256
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_hash_sha256(byte[] hash, byte[] message, long messageLength);

        // crypto_generichash
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_generichash(byte[] hash, int hashLength, byte[] message, long messageLength, byte[] key, int keyLength);

        // crypto_generichash_blake2b_salt_personal
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_generichash_blake2b_salt_personal(byte[] hash, int hashLength, byte[] message, long messageLength, byte[] key, int keyLength, byte[] salt, byte[] personal);

        // crypto_onetimeauth
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_onetimeauth(byte[] tag, byte[] message, long messageLength, byte[] key);

        // crypto_onetimeauth_verify
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_onetimeauth_verify(byte[] tag, byte[] message, long messageLength, byte[] key);

        // crypto_pwhash_str
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_pwhash_str(byte[] hash, byte[] password, long passwordLength, long iterations, int memorySize);

        // crypto_pwhash_str_verify
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_pwhash_str_verify(byte[] hash, byte[] password, long passwordLength);

        // crypto_pwhash
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_pwhash(byte[] hash, long hashLen, byte[] password, long passwordLength, byte[] salt, long iterations, int memorySize, int algorithm);

        // crypto_pwhash_str_needs_rehash
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_pwhash_str_needs_rehash(byte[] hash, long iterations, int memorySize);

        // crypto_pwhash_scryptsalsa208sha256_str
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str(byte[] hash, byte[] password, long passwordLength, long blockSize, int memorySize);

        // crypto_pwhash_scryptsalsa208sha256
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256(byte[] hash, long hashLen, byte[] password, long passwordLength, byte[] salt, long blockSize, int memorySize);

        // crypto_pwhash_scryptsalsa208sha256_str_verify
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str_verify(byte[] hash, byte[] password, long passwordLength);

        // crypto_sign_keypair
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_sign_keypair(byte[] publicKey, byte[] privateKey);

        // crypto_sign_seed_keypair
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_sign_seed_keypair(byte[] publicKey, byte[] privateKey, byte[] seed);

        // crypto_sign
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_sign(byte[] signedMessage, ref long signedMessageLength, byte[] message, long messageLength, byte[] key);

        // crypto_sign_open
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_sign_open(byte[] message, ref long messageLength, byte[] signedMessage, long signedMessageLength, byte[] key);

        // crypto_sign_detached
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_sign_detached(byte[] signature, ref long signatureLength, byte[] message, long messageLength, byte[] key);

        // crypto_sign_verify_detached
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_sign_verify_detached(byte[] signature, byte[] message, long messageLength, byte[] key);

        // crypto_sign_ed25519_sk_to_seed
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_sign_ed25519_sk_to_seed(byte[] seed, byte[] privateKey);

        // crypto_sign_ed25519_sk_to_pk
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_sign_ed25519_sk_to_pk(byte[] publicKey, byte[] privateKey);

        // crypto_sign_ed25519_pk_to_curve25519
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_sign_ed25519_pk_to_curve25519(byte[] x25519PublicKey, byte[] ed25519PublicKey);

        // crypto_sign_ed25519_sk_to_curve25519
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_sign_ed25519_sk_to_curve25519(byte[] x25519PrivateKey, byte[] ed25519PrivateKey);

        // crypto_box_keypair
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_box_keypair(byte[] publicKey, byte[] privateKey);

        // crypto_box_seed_keypair
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_box_seed_keypair(byte[] publicKey, byte[] privateKey, byte[] seed);

        // crypto_box_easy
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_box_easy(byte[] ciphertext, byte[] message, long messageLength, byte[] nonce, byte[] publicKey, byte[] privateKey);

        //// crypto_box_open_easy
        //[DllImport(_dllName, CallingConvention = _callingConvention)]
        //internal static extern int crypto_box_detached(byte[] ciphertext, byte[] tag, byte[] message, long messageLength, byte[] nonce, byte[] publicKey, byte[] privateKey);

        // crypto_box_detached
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_box_open_easy(byte[] message, byte[] ciphertext, long ciphertextLength, byte[] nonce, byte[] publicKey, byte[] privateKey);

        //// crypto_box_open_detached
        //[DllImport(_dllName, CallingConvention = _callingConvention)]
        //internal static extern int crypto_box_open_detached(byte[] message, byte[] ciphertext, byte[] tag, long ciphertextLength, byte[] nonce, byte[] publicKey, byte[] privateKey);

        //// crypto_box_seedbytes
        //[DllImport(_dllName, CallingConvention = _callingConvention)]
        //internal static extern int crypto_box_seedbytes();

        //// crypto_scalarmult_bytes
        //[DllImport(_dllName, CallingConvention = _callingConvention)]
        //internal static extern int crypto_scalarmult_bytes();

        //// crypto_scalarmult_scalarbytes
        //[DllImport(_dllName, CallingConvention = _callingConvention)]
        //internal static extern int crypto_scalarmult_scalarbytes();

        //// crypto_scalarmult_primitive
        //[DllImport(_dllName, CallingConvention = _callingConvention)]
        //internal static extern byte crypto_scalarmult_primitive();

        // crypto_scalarmult_base
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_scalarmult_base(byte[] publicKey, byte[] privateKey);

        // crypto_scalarmult
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_scalarmult(byte[] sharedSecret, byte[] privateKey, byte[] publicKey);

        // crypto_box_seal
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_box_seal(byte[] ciphertext, byte[] message, long messageLength, byte[] publicKey);

        // crypto_box_seal_open
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_box_seal_open(byte[] message, byte[] ciphertext, long ciphertextLength, byte[] publicKey, byte[] privateKey);

        // crypto_secretbox_easy
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_secretbox_easy(byte[] ciphertext, byte[] message, long messageLength, byte[] nonce, byte[] key);

        // crypto_secretbox_open_easy
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_secretbox_open_easy(byte[] message, byte[] ciphertext, long ciphertextLength, byte[] nonce, byte[] key);

        //// crypto_secretbox_detached
        //[DllImport(_dllName, CallingConvention = _callingConvention)]
        //internal static extern int crypto_secretbox_detached(byte[] ciphertext, byte[] tag, byte[] message, long messageLength, byte[] nonce, byte[] key);

        //// crypto_secretbox_open_detached
        //[DllImport(_dllName, CallingConvention = _callingConvention)]
        //internal static extern int crypto_secretbox_open_detached(byte[] message, byte[] ciphertext, byte[] tag, long ciphertextLength, byte[] nonce, byte[] key);

        // crypto_auth
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_auth(byte[] hash, byte[] message, long messageLength, byte[] key);

        // crypto_auth_verify
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_auth_verify(byte[] tag, byte[] message, long messageLength, byte[] key);

        // crypto_auth_hmacsha256
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_auth_hmacsha256(byte[] hash, byte[] message, long messageLength, byte[] key);

        // crypto_auth_hmacsha256_verify
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_auth_hmacsha256_verify(byte[] tag, byte[] message, long messageLength, byte[] key);

        // crypto_auth_hmacsha512
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_auth_hmacsha512(byte[] hash, byte[] message, long messageLength, byte[] key);

        // crypto_auth_hmacsha512_verify
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_auth_hmacsha512_verify(byte[] tag, byte[] message, long messageLength, byte[] key);

        // crypto_shorthash
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_shorthash(byte[] hash, byte[] message, long messageLength, byte[] key);

        //// crypto_shorthash_siphashx24
        //[DllImport(_dllName, CallingConvention = _callingConvention)]
        //internal static extern int crypto_shorthash_siphashx24(byte[] hash, byte[] message, long messageLength, byte[] key);

        // crypto_stream_xor
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_stream_xor(byte[] ciphertext, byte[] message, long messageLength, byte[] nonce, byte[] key);

        // crypto_stream_chacha20_xor
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_stream_chacha20_xor(byte[] ciphertext, byte[] message, long messageLength, byte[] nonce, byte[] key);

        // sodium_bin2hex
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern IntPtr sodium_bin2hex(byte[] hex, int hexLength, byte[] binary, int binaryLength);

        // sodium_hex2bin
        [DllImport(_dllName, CallingConvention = _callingConvention, CharSet = CharSet.Unicode)]
        internal static extern int sodium_hex2bin(IntPtr binaryPointer, int binaryLength, string hex, int hexLength, string ignoredChars, out int decodedLength, string hexEnd);

        // sodium_bin2base64
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern IntPtr sodium_bin2base64(byte[] base64, int base64Length, byte[] binary, int binaryLength, int base64Variant);

        // sodium_base642bin
        [DllImport(_dllName, CallingConvention = _callingConvention, CharSet = CharSet.Unicode)]
        internal static extern int sodium_base642bin(IntPtr binaryPointer, int binaryLength, string base64, int base64Length, string ignoredChars, out int decodedLength, out char base64End, int base64Variant);

        // sodium_base64_encoded_len
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int sodium_base64_encoded_len(int binaryLength, int base64Variant);

        // crypto_aead_chacha20poly1305_ietf_encrypt
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_aead_chacha20poly1305_ietf_encrypt(IntPtr ciphertext, out long ciphertextLength, byte[] message, long messageLength, byte[] additionalData, long additionalDataLength, byte[] nsec, byte[] nonce, byte[] key);

        // crypto_aead_chacha20poly1305_ietf_decrypt
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_aead_chacha20poly1305_ietf_decrypt(IntPtr message, out long messageLength, byte[] nsec, byte[] ciphertext, long ciphertextLength, byte[] additionalData, long additionalDataLength, byte[] nonce, byte[] key);

        // crypto_aead_chacha20poly1305_encrypt
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_aead_chacha20poly1305_encrypt(IntPtr ciphertext, out long ciphertextLength, byte[] message, long messageLength, byte[] additionalData, long additionalDataLength, byte[] nsec, byte[] nonce, byte[] key);

        // crypto_aead_chacha20poly1305_decrypt
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_aead_chacha20poly1305_decrypt(IntPtr message, out long messageLength, byte[] nsec, byte[] ciphertext, long ciphertextLength, byte[] additionalData, long additionalDataLength, byte[] nonce, byte[] key);

        // crypto_aead_xchacha20poly1305_ietf_encrypt
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_encrypt(IntPtr ciphertext, out long ciphertextLength, byte[] message, long messageLength, byte[] additionalData, long additionalDataLength, byte[] nsec, byte[] nonce, byte[] key);

        // crypto_aead_xchacha20poly1305_ietf_decrypt
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_decrypt(IntPtr message, out long messageLength, byte[] nsec, byte[] ciphertext, long ciphertextLength, byte[] additionalData, long additionalDataLength, byte[] nonce, byte[] key);

        // crypto_aead_aes256gcm_is_available
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_aead_aes256gcm_is_available();

        // crypto_aead_aes256gcm_encrypt
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_aead_aes256gcm_encrypt(IntPtr ciphertextPointer, out long ciphertextLength, byte[] message, long messageLength, byte[] additionalData, long additionalDataLength, byte[] nsec, byte[] nonce, byte[] key);

        // crypto_aead_aes256gcm_decrypt
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_aead_aes256gcm_decrypt(IntPtr message, out long messageLength, byte[] nsec, byte[] ciphertext, long ciphertextLength, byte[] additionalData, long additionalDataLength, byte[] nonce, byte[] key);

        // crypto_generichash_init
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_generichash_init(IntPtr state, byte[] key, int keySize, int hashSize);

        // crypto_generichash_update
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_generichash_update(IntPtr state, byte[] message, long messageLength);

        // crypto_generichash_final
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_generichash_final(IntPtr state, byte[] hash, int hashLength);

        // crypto_generichash_state
        [StructLayout(LayoutKind.Sequential, Size = 384)]
        internal struct HashState
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public ulong[] h;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ulong[] t;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ulong[] f;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public byte[] buf;

            public uint buflen;

            public byte last_node;
        }

        //// crypto_stream_xchacha20
        //[DllImport(_dllName, CallingConvention = _callingConvention)]
        //internal static extern int crypto_stream_xchacha20(byte[] ciphertext, int ciphertextLength, byte[] nonce, byte[] key);

        // crypto_stream_xchacha20_xor
        [DllImport(_dllName, CallingConvention = _callingConvention)]
        internal static extern int crypto_stream_xchacha20_xor(byte[] ciphertext, byte[] message, long messageLength, byte[] nonce, byte[] key);
    }
}
