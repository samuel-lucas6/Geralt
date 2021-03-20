using System.Text;

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
    /// <summary>Hashing using SHA2.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/advanced/sha-2_hash_function </remarks>
    public class SHA2
    {
        private const int _sha512Bytes = 64;
        private const int _sha256Bytes = 32;

        /// <summary>Hashes a string using SHA512.</summary>
        /// <param name="message">The message.</param>
        /// <returns>A 64 byte hash.</returns>
        public static byte[] Hash(string message)
        {
            return Hash(Encoding.UTF8.GetBytes(message));
        }

        /// <summary>Hashes a byte array using SHA512.</summary>
        /// <param name="message">The message.</param>
        /// <returns>A 64 byte hash.</returns>
        public static byte[] Hash(byte[] message)
        {
            byte[] hash = new byte[_sha512Bytes];
            _ = LibsodiumLibrary.crypto_hash(hash, message, message.Length);
            return hash;
        }

        /// <summary>Hashes a string using SHA512.</summary>
        /// <param name="message">The message.</param>
        /// <returns>A 64 byte hash.</returns>
        public static byte[] Sha512(string message)
        {
            return Sha512(Encoding.UTF8.GetBytes(message));
        }

        /// <summary>Hashes a byte array using SHA512.</summary>
        /// <param name="message">The message.</param>
        /// <returns>A 64 byte hash.</returns>
        public static byte[] Sha512(byte[] message)
        {
            byte[] hash = new byte[_sha512Bytes];
            _ = LibsodiumLibrary.crypto_hash_sha512(hash, message, message.Length);
            return hash;
        }

        /// <summary>Hashes a string using SHA256.</summary>
        /// <param name="message">The message.</param>
        /// <returns>A 32 byte hash.</returns>
        public static byte[] Sha256(string message)
        {
            return Sha256(Encoding.UTF8.GetBytes(message));
        }

        /// <summary>Hashes a byte array using SHA256.</summary>
        /// <param name="message">The message.</param>
        /// <returns>A 32 byte hash.</returns>
        public static byte[] Sha256(byte[] message)
        {
            byte[] hash = new byte[_sha256Bytes];
            _ = LibsodiumLibrary.crypto_hash_sha256(hash, message, message.Length);
            return hash;
        }
    }
}
