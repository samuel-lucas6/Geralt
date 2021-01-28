using Geralt.Exceptions;
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
    /// <summary>Compute a message authentication code using HMAC.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/advanced/hmac-sha2 </remarks>
    public static class HMAC
    {
        private const int _keyBytes = 32;
        private const int _hmacSHA256Bytes = 32;
        private const int _hmacSHA512Bytes = 64;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>A byte array with 32 random bytes.</returns>
        public static byte[] GenerateKey()
        {
            return SecureRandom.GetBytes(_keyBytes);
        }

        /// <summary>Computes a message authentication code using HMAC-SHA512-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The 32 byte message authentication code.</returns>
        public static byte[] Compute(string message, byte[] key)
        {
            return Compute(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Computes a message authentication code using HMAC-SHA512-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The 32 byte message authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Compute(byte[] message, byte[] key)
        {
            ParameterValidation.Key(key, _keyBytes);
            byte[] hash = new byte[_hmacSHA256Bytes];
            _ = LibsodiumLibrary.crypto_auth(hash, message, message.Length, key);
            return hash;
        }

        /// <summary>Verifies a message authentication code using HMAC-SHA512-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The 32 byte message authentication code.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(string message, byte[] tag, byte[] key)
        {
            return Verify(Encoding.UTF8.GetBytes(message), tag, key);
        }

        /// <summary>Verifies a message authentication code using HMAC-SHA512-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The 32 byte message authentication code.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(byte[] message, byte[] tag, byte[] key)
        {
            ParameterValidation.Key(key, _keyBytes);
            ParameterValidation.Signature(tag, _hmacSHA256Bytes);
            int result = LibsodiumLibrary.crypto_auth_verify(tag, message, message.Length, key);
            return result == 0;
        }

        /// <summary>Computes a message authentication code using HMAC-SHA256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The 32 byte message authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] ComputeSHA256(byte[] message, byte[] key)
        {
            ParameterValidation.Key(key, _keyBytes);
            byte[] hash = new byte[_hmacSHA256Bytes];
            _ = LibsodiumLibrary.crypto_auth_hmacsha256(hash, message, message.Length, key);
            return hash;
        }

        /// <summary>Computes a message authentication code using HMAC-SHA256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The 32 byte message authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] ComputeSHA256(string message, byte[] key)
        {
            return ComputeSHA256(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Computes a message authentication code using HMAC-SHA512.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The 64 byte message authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] ComputeSHA512(byte[] message, byte[] key)
        {
            ParameterValidation.Key(key, _keyBytes);
            byte[] hash = new byte[_hmacSHA512Bytes];
            _ = LibsodiumLibrary.crypto_auth_hmacsha512(hash, message, message.Length, key);
            return hash;
        }

        /// <summary>Computes a message authentication code using HMAC-SHA512.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The 64 byte message authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] ComputeSHA512(string message, byte[] key)
        {
            return ComputeSHA512(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Verifies a message authentication code using HMAC-SHA256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The 32 byte message authentication code.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifySHA256(string message, byte[] tag, byte[] key)
        {
            return VerifySHA256(Encoding.UTF8.GetBytes(message), tag, key);
        }

        /// <summary>Verifies a message authentication code using HMAC-SHA256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The 32 byte message authentication code.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifySHA256(byte[] message, byte[] tag, byte[] key)
        {
            ParameterValidation.Key(key, _keyBytes);
            ParameterValidation.Signature(tag, _hmacSHA256Bytes);
            int result = LibsodiumLibrary.crypto_auth_hmacsha256_verify(tag, message, message.Length, key);
            return result == 0;
        }

        /// <summary>Verifies a message authentication code using HMAC-SHA512.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The 64 byte message authentication code.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifySHA512(string message, byte[] tag, byte[] key)
        {
            return VerifySHA512(Encoding.UTF8.GetBytes(message), tag, key);
        }

        /// <summary>Verifies a message authentication code using HMAC-SHA512.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The 64 byte message authentication code.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifySHA512(byte[] message, byte[] tag, byte[] key)
        {
            ParameterValidation.Key(key, _keyBytes);
            ParameterValidation.Signature(tag, _hmacSHA512Bytes);
            int result = LibsodiumLibrary.crypto_auth_hmacsha512_verify(tag, message, message.Length, key);
            return result == 0;
        }
    }
}
