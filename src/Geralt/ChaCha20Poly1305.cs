using Geralt.Exceptions;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

/*
    Geralt: libsodium for .NET - A fast, secure, and modern cryptographic library.
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
    /// <summary>Authenticated encryption with additional data using ChaCha20-Poly1305.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/original_chacha20-poly1305_construction </remarks>
    public static class ChaCha20Poly1305
    {
        private const int _keyBytes = 32;
        private const int _nonceBytes = 8;
        private const int _tagBytes = 16;

        /// <summary>Generates a random 8 byte nonce.</summary>
        /// <returns>A byte array with 8 random bytes.</returns>
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

        /// <summary>Encrypts a message using ChaCha20-Poly1305.</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">The additional data - can be null.</param>
        /// <returns>The encrypted message with an authentication tag.</returns>
        /// <remarks>Never reuse a nonce with the same key. A counter nonce is recommended.</remarks>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key, byte[] additionalData = null)
        {
            additionalData = ParameterValidation.AdditionalData(additionalData);
            ParameterValidation.Key(key, _keyBytes);
            ParameterValidation.Nonce(nonce, _nonceBytes);
            byte[] ciphertext = new byte[message.Length + _tagBytes];
            IntPtr ciphertextPointer = Marshal.AllocHGlobal(ciphertext.Length);
            int result = LibsodiumLibrary.crypto_aead_chacha20poly1305_encrypt(ciphertextPointer, out long ciphertextLength, message, message.Length, additionalData, additionalData.Length, nsec: null, nonce, key);
            Marshal.Copy(ciphertextPointer, ciphertext, startIndex: 0, (int)ciphertextLength);
            Marshal.FreeHGlobal(ciphertextPointer);
            if (result != 0)
            {
                throw new CryptographicException("Error encrypting message.");
            }
            return ciphertext.Length == ciphertextLength ? ciphertext : NullPadding.RemoveTrailingNulls(ciphertext, ciphertextLength);
        }

        /// <summary>Decrypts a ciphertext message using ChaCha20-Poly1305.</summary>
        /// <param name="ciphertext">The ciphertext to be decrypted.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">The additional data - can be null.</param>
        /// <returns>The decrypted ciphertext.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] key, byte[] additionalData = null)
        {
            additionalData = ParameterValidation.AdditionalData(additionalData);
            ParameterValidation.Key(key, _keyBytes);
            ParameterValidation.Nonce(nonce, _nonceBytes);
            byte[] message = new byte[ciphertext.Length - _tagBytes];
            IntPtr messagePointer = Marshal.AllocHGlobal(message.Length);
            int result = LibsodiumLibrary.crypto_aead_chacha20poly1305_decrypt(messagePointer, out long messageLength, nsec: null, ciphertext, ciphertext.Length, additionalData, additionalData.Length, nonce, key);
            Marshal.Copy(messagePointer, message, startIndex: 0, (int)messageLength);
            Marshal.FreeHGlobal(messagePointer);
            if (result != 0)
            {
                throw new CryptographicException("Error decrypting message.");
            }
            return message.Length == messageLength ? message : NullPadding.RemoveTrailingNulls(message, messageLength);
        }
    }
}
