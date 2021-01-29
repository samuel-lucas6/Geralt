using Geralt.Exceptions;
using System;
using System.Security.Cryptography;
using System.Text;

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
    /// <summary>Authenticated encryption using XSalsa20-Poly1305.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/secret-key_cryptography/secretbox </remarks>
    public static class XSalsa20Poly1305
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

        /// <summary>Encrypts a message using XSalsa20-Poly1305.</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message with an authentication tag.</returns>
        /// <remarks>The nonce should never be reused with the same key.</remarks>
        /// <remarks>The recommended way to generate a nonce is to use GenerateNonce() for the first message and increment it for each subsequent message using the same key.</remarks>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key)
        {
            ParameterValidation.Key(key, _keyBytes);
            ParameterValidation.Nonce(nonce, _nonceBytes);
            byte[] ciphertext = new byte[_tagBytes + message.Length];
            int result = LibsodiumLibrary.crypto_secretbox_easy(ciphertext, message, message.Length, nonce, key);
            ResultValidation.EncryptResult(result);
            return ciphertext;
        }

        /// <summary>Decrypts a ciphertext message using XSalsa20-Poly1305.</summary>
        /// <param name="ciphertext">The ciphertext to be decrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted ciphertext.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] key)
        {
            ParameterValidation.Key(key, _keyBytes);
            ParameterValidation.Nonce(nonce, _nonceBytes);
            ciphertext = NullPadding.RemoveLeadingNulls(ciphertext, _tagBytes);
            var message = new byte[ciphertext.Length - _tagBytes];
            int result = LibsodiumLibrary.crypto_secretbox_open_easy(message, ciphertext, ciphertext.Length, nonce, key);
            ResultValidation.DecryptResult(result);
            return message;
        }
    }
}
