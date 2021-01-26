using System.Text;
using Geralt.Exceptions;

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
    /// <summary>Hashing using SipHash-2-4.</summary>
    public static class SipHash
    {
        private const int _hashBytes = 8;
        private const int _keyBytes = 16;

        /// <summary>Generates a random 16 byte key.</summary>
        /// <returns>A byte array with 16 random bytes.</returns>
        public static byte[] GenerateKey()
        {
            return GeraltCore.GetRandomBytes(_keyBytes);
        }

        /// <summary>Hashes a message with a key using SipHash-2-4.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">A 16 byte key.</param>
        /// <returns>An 8 byte hash.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Hash(string message, string key)
        {
            return Hash(message, Encoding.UTF8.GetBytes(key));
        }

        /// <summary>Hashes a message with a key using SipHash-2-4.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">A 16 byte key.</param>
        /// <returns>An 8 byte hash.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Hash(string message, byte[] key)
        {
            return Hash(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Hashes a message with a key using SipHash-2-4.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">A 16 byte key.</param>
        /// <returns>An 8 byte hash.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Hash(byte[] message, byte[] key)
        {
            if (key == null || key.Length != _keyBytes)
            {
                throw new KeyOutOfRangeException(nameof(key), (key == null) ? 0 : key.Length, $"Key must be {_keyBytes} bytes in length.");
            }
            byte[] hash = new byte[_hashBytes];
            _ = LibsodiumLibrary.crypto_shorthash(hash, message, message.Length, key);
            return hash;
        }
    }
}
