﻿using System.IO;

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
    /// <summary>Hashing using SHA512.</summary>
    public class SHA512
    {
        public const int HashLength = 64;

        /// <summary>Hashes a byte array using SHA512.</summary>
        /// <param name="message">The message.</param>
        /// <returns>A 64 byte hash.</returns>
        public static byte[] ComputeHash(byte[] message)
        {
            byte[] hash = new byte[HashLength];
            _ = LibsodiumLibrary.crypto_hash_sha512(hash, message, message.Length);
            return hash;
        }

        /// <summary>Hashes a byte array using SHA512.</summary>
        /// <param name="message">The message.</param>
        /// <returns>A 64 byte hash.</returns>
        public static byte[] ComputeHash(Stream message)
        {
            using var sha512 = System.Security.Cryptography.SHA512.Create();
            return sha512.ComputeHash(message);
        }
    }
}