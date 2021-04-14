using Geralt.Exceptions;
using System;
using System.IO;

/*
    Geralt: A cryptographic library for .NET based on libsodium.
    Copyright (c) 2021 Samuel Lucas

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
    /// <summary>Hashing, keyed hashing, and key derivation using BLAKE2b-128.</summary>
    /// <remarks>Note that <see cref="BLAKE2b_256"/> is strongly recommended over <see cref="BLAKE2b_128"/>.</remarks>
    public static class BLAKE2b_128
    {
        public const int HashSize = 16;
        public const int KeySize = 32;
        public const int SaltSize = 16;
        public const int ContextSize = 16;

        /// <summary>Hashes a message using BLAKE2b-128.</summary>
        /// <remarks>Note that <see cref="BLAKE2b_256"/> is strongly recommended.</remarks>
        /// <param name="message">The message to be hashed.</param>
        /// <returns>The hash of the message.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] ComputeHash(byte[] message)
        {
            return BLAKE2b.ComputeHash(message, HashSize);
        }

        /// <summary>Hashes a message using BLAKE2b-128.</summary>
        /// <remarks>Note that <see cref="BLAKE2b_256"/> is strongly recommended.</remarks>
        /// <param name="message">The message to be hashed.</param>
        /// <returns>The hash of the message.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] ComputeHash(Stream message)
        {
            return BLAKE2b.ComputeHash(message, HashSize);
        }

        /// <summary>Computes a MAC using BLAKE2b-128.</summary>
        /// <remarks>Note that <see cref="BLAKE2b_256"/> is strongly recommended.</remarks>
        /// <param name="message">The message to be authenticated.</param>
        /// <param name="key">The 16-64 byte key.</param>
        /// <returns>The computed authentication tag.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] ComputeMAC(byte[] message, byte[] key)
        {
            return BLAKE2b.ComputeMAC(message, key, HashSize);
        }

        /// <summary>Computes a MAC using BLAKE2b-128.</summary>
        /// <remarks>Note that <see cref="BLAKE2b_256"/> is strongly recommended.</remarks>
        /// <param name="message">The message to be authenticated.</param>
        /// <param name="key">The 16-64 byte key.</param>
        /// <returns>The computed authentication tag.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] ComputeHash(Stream message, byte[] key)
        {
            return BLAKE2b.ComputeMAC(message, key, HashSize);
        }

        /// <summary>Verifies a BLAKE2b-128 authentication tag.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The authentication tag.</param>
        /// <param name="key">The 16-64 byte key.</param>
        /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="TagOutOfRangeException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static bool VerifyMAC(byte[] message, byte[] tag, byte[] key)
        {
            return BLAKE2b.VerifyMAC(message, tag, key);
        }

        /// <summary>Verifies a BLAKE2b-128 authentication tag appended to the message.</summary>
        /// <param name="message">The message and authentication tag.</param>
        /// <param name="key">The key.</param>
        /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static bool VerifyMAC(byte[] message, byte[] key)
        {
            return BLAKE2b.VerifyMAC(message, key, HashSize);
        }

        /// <summary>Verifies a BLAKE2b-128 authentication tag appended to the message.</summary>
        /// <param name="message">The message and authentication tag.</param>
        /// <param name="key">The key.</param>
        /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static bool VerifyMAC(Stream message, byte[] key)
        {
            return BLAKE2b.VerifyMAC(message, key, HashSize);
        }

        /// <summary>Derives a 16 byte subkey from a high-entropy master key.</summary>
        /// <remarks>Note that <see cref="BLAKE2b_256"/> is strongly recommended.</remarks>
        /// <param name="inputKeyingMaterial">The high-entropy master key.</param>
        /// <param name="salt">The 16 byte random or counter salt.</param>
        /// <param name="context">The 16 character context string.</param>
        /// <param name="message">An optional message to be included in the hash.</param>
        /// <returns>The derived subkey.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="ContextOutOfRangeException"></exception>
        public static byte[] DeriveKey(byte[] inputKeyingMaterial, byte[] salt, string context, byte[] message = null)
        {
            return BLAKE2b.DeriveKey(inputKeyingMaterial, salt, context, HashSize, message);
        }

        /// <summary>Derives a 16 byte subkey from a high-entropy master key.</summary>
        /// <remarks>Note that <see cref="BLAKE2b_256"/> is strongly recommended.</remarks>
        /// <param name="inputKeyingMaterial">The high-entropy master key.</param>
        /// <param name="salt">The 16 byte random or counter salt.</param>
        /// <param name="context">The 16 byte context information.</param>
        /// <param name="message">An optional message to be included in the hash.</param>
        /// <returns>The derived subkey.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="ContextOutOfRangeException"></exception>
        public static byte[] DeriveKey(byte[] inputKeyingMaterial, byte[] salt, byte[] context, byte[] message = null)
        {
            return BLAKE2b.DeriveKey(inputKeyingMaterial, salt, context, HashSize, message);
        }
    }
}
