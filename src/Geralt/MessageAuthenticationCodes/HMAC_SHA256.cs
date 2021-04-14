using Geralt.Exceptions;
using System;
using System.Security.Cryptography;
using System.IO;

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
    /// <summary>Compute a message authentication code using HMAC-SHA256.</summary>
    public static class HMAC_SHA256
    {
        public const int KeySize = 32;
        public const int HashSize = 32;

        /// <summary>Computes a message authentication code using HMAC-SHA256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The 32 byte message authentication code.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] ComputeMAC(byte[] message, byte[] key)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Key(key, KeySize);
            byte[] hash = new byte[HashSize];
            _ = LibsodiumLibrary.crypto_auth_hmacsha256(hash, message, message.Length, key);
            return hash;
        }

        /// <summary>Computes a message authentication code using HMAC-SHA256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The 32 byte message authentication code.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] ComputeMAC(Stream message, byte[] key)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Key(key, KeySize);
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(message);
        }

        /// <summary>Verifies a message authentication code using HMAC-SHA256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The 32 byte message authentication code.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="TagOutOfRangeException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static bool VerifyMAC(byte[] message, byte[] tag, byte[] key)
        {
            ParameterValidation.Key(key, KeySize);
            ParameterValidation.Tag(tag, HashSize);
            int result = LibsodiumLibrary.crypto_auth_hmacsha256_verify(tag, message, message.Length, key);
            return result == 0;
        }

        /// <summary>Verifies a HMAC-SHA256 authentication tag appended to the message.</summary>
        /// <param name="message">The message and authentication tag.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static bool VerifyMAC(byte[] message, byte[] key)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Key(key, KeySize);
            byte[] tag = new byte[HashSize];
            Array.Copy(message, sourceIndex: message.Length - tag.Length, tag, destinationIndex: 0, tag.Length);
            byte[] computedTag = ComputeMAC(message, key);
            return ConstantTime.Compare(tag, computedTag);
        }

        /// <summary>Verifies a HMAC-SHA256 authentication tag appended to the message.</summary>
        /// <param name="message">The message and authentication tag.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static bool VerifyMAC(Stream message, byte[] key)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Key(key, KeySize);
            message.Seek(-HashSize, SeekOrigin.End);
            byte[] tag = new byte[HashSize];
            message.Read(tag, offset: 0, tag.Length);
            message.Seek(offset: 0, SeekOrigin.Begin);
            using var hmac = new HMACSHA256(key);
            byte[] computedTag = hmac.ComputeHash(message);
            return ConstantTime.Compare(tag, computedTag);
        }
    }
}
