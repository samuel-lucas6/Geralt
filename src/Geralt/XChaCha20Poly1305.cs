using Geralt.Exceptions;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

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
    /// <summary>Authenticated encryption with additional data using XChaCha20-Poly1305.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction </remarks>
    public static class XChaCha20Poly1305
    {
        private const int _keyBytes = 32;
        private const int _nonceBytes = 24;
        private const int _tagBytes = 16;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>A byte array with 32 random bytes.</returns>
        public static byte[] GenerateKey()
        {
            return SecureRandom.GetBytes(_keyBytes);
        }

        /// <summary>Generates a random 24 byte nonce.</summary>
        /// <returns>A byte array with 24 random bytes.</returns>
        public static byte[] GenerateNonce()
        {
            return SecureRandom.GetBytes(_nonceBytes);
        }

        /// <summary>Increments a nonce in constant time.</summary>
        /// <param name="nonce">The nonce to increment.</param>
        /// <returns>The incremented byte array.</returns>
        public static byte[] IncrementNonce(byte[] nonce)
        {
            return ConstantTime.Increment(nonce);
        }

        /// <summary>Encrypts a message using XChaCha20-Poly1305.</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">The additional data - can be null.</param>
        /// <returns>The encrypted message with an authentication tag.</returns>
        /// <remarks>The nonce should never be reused with the same key.</remarks>
        /// <remarks>The recommended way to generate a nonce is to use GenerateNonce() for the first message and increment it for each subsequent message using the same key.</remarks>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key, byte[] additionalData = null)
        {
            additionalData = ParameterValidation.AdditionalData(additionalData);
            ParameterValidation.Nonce(nonce, _nonceBytes);
            ParameterValidation.Key(key, _keyBytes);
            byte[] ciphertext = new byte[message.Length + _tagBytes];
            IntPtr ciphertextPointer = Marshal.AllocHGlobal(ciphertext.Length);
            int result = LibsodiumLibrary.crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertextPointer, out long ciphertextLength, message, message.Length, additionalData, additionalData.Length, nsec: null, nonce, key);
            Marshal.Copy(ciphertextPointer, ciphertext, startIndex: 0, (int)ciphertextLength);
            Marshal.FreeHGlobal(ciphertextPointer);
            ResultValidation.EncryptResult(result);
            return ciphertext.Length == ciphertextLength ? ciphertext : NullPadding.RemoveTrailingNulls(ciphertext, ciphertextLength);
        }

        /// <summary>Decrypts a ciphertext message using XChaCha20-Poly1305.</summary>
        /// <param name="ciphertext">The ciphertext to be decrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">The additional data - can be null.</param>
        /// <returns>The decrypted ciphertext.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] key, byte[] additionalData = null)
        {
            additionalData = ParameterValidation.AdditionalData(additionalData);
            ParameterValidation.Nonce(nonce, _nonceBytes);
            ParameterValidation.Key(key, _keyBytes);
            byte[] plaintext = new byte[ciphertext.Length - _tagBytes];
            IntPtr plaintextPointer = Marshal.AllocHGlobal(plaintext.Length);
            int result = LibsodiumLibrary.crypto_aead_xchacha20poly1305_ietf_decrypt(plaintextPointer, out long plaintextLength, nsec: null, ciphertext, ciphertext.Length, additionalData, additionalData.Length, nonce, key);
            Marshal.Copy(plaintextPointer, plaintext, startIndex: 0, (int)plaintextLength);
            Marshal.FreeHGlobal(plaintextPointer);
            ResultValidation.DecryptResult(result);
            return plaintext.Length == plaintextLength ? plaintext : NullPadding.RemoveTrailingNulls(plaintext, plaintextLength);
        }
    }
}
