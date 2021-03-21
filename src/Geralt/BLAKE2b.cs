using Geralt.Exceptions;
using System;
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
    /// <summary>Hashing, keyed hashing, and key derivation using BLAKE2b.</summary>
    public partial class BLAKE2b
    {
        public const int KeySize = 32;
        public const int SaltSize = 16;
        public const int ContextSize = 16;
        public const int HashLength = 64;
        public const int MACLength = 32;
        private const int _minLength = 16;
        private const int _maxLength = 64;
        private const int _minKeySize = 16;
        private const int _maxKeySize = 64;

        /// <summary>Hashes a message using BLAKE2b.</summary>
        /// <remarks>The output length should be 32 or 64 bytes.</remarks>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="length">The length of the hash in bytes.</param>
        /// <returns>The hash of the message.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="LengthOutOfRangeException"></exception>
        public static byte[] Hash(byte[] message, int length = HashLength)
        {
            return MAC(message, key: null, length);
        }

        /// <summary>Computes a MAC using BLAKE2b.</summary>
        /// <remarks>The authentication tag length should be 32 or 64 bytes.</remarks>
        /// <param name="message">The message to be authenticated.</param>
        /// <param name="key">The 32 or 64 byte key.</param>
        /// <param name="length">The length of the authentication tag in bytes.</param>
        /// <returns>The computed authentication tag.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="LengthOutOfRangeException"></exception>
        public static byte[] MAC(byte[] message, byte[] key, int length = MACLength)
        {
            ParameterValidation.Message(message);
            key = ParameterValidation.Key(key, _minKeySize, _maxKeySize);
            ParameterValidation.OutputLength(length, _minLength, _maxLength);
            byte[] hash = new byte[length];
            _ = LibsodiumLibrary.crypto_generichash(hash, hash.Length, message, message.Length, key, key.Length);
            return hash;
        }

        /// <summary>Derives a subkey from a master key.</summary>
        /// <remarks>The subkey length should be 32 or 64 bytes.</remarks>
        /// <param name="inputKeyingMaterial">The master key.</param>
        /// <param name="salt">The 16 byte random or counter salt.</param>
        /// <param name="context">The 16 character context string.</param>
        /// <param name="length">The subkey size in bytes.</param>
        /// <param name="message">An optional message to be included in the hash.</param>
        /// <returns>The derived subkey.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="ContextOutOfRangeException"></exception>
        /// <exception cref="LengthOutOfRangeException"></exception>
        public static byte[] DeriveKey(byte[] inputKeyingMaterial, byte[] salt, string context, int length = KeySize, byte[] message = null)
        {
            return DeriveKey(inputKeyingMaterial, salt, Encoding.UTF8.GetBytes(context), length, message);
        }

        /// <summary>Derives a subkey from a master key.</summary>
        /// <remarks>The subkey length should be 32 or 64 bytes.</remarks>
        /// <param name="inputKeyingMaterial">The master key.</param>
        /// <param name="salt">The 16 byte random or counter salt.</param>
        /// <param name="context">The 16 byte context information.</param>
        /// <param name="length">The subkey size in bytes.</param>
        /// <param name="message">An optional message to be included in the hash.</param>
        /// <returns>The derived subkey.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="ContextOutOfRangeException"></exception>
        /// <exception cref="LengthOutOfRangeException"></exception>
        public static byte[] DeriveKey(byte[] inputKeyingMaterial, byte[] salt, byte[] context, int length = KeySize, byte[] message = null)
        {
            inputKeyingMaterial = ParameterValidation.Key(inputKeyingMaterial, _minKeySize, _maxKeySize);
            ParameterValidation.Salt(salt, SaltSize);
            ParameterValidation.Context(context, ContextSize);
            ParameterValidation.OutputLength(length, _minLength, _maxLength);
            if (message == null) { message = Array.Empty<byte>(); }
            byte[] hash = new byte[length];
            _ = LibsodiumLibrary.crypto_generichash_blake2b_salt_personal(hash, hash.Length, message, message.Length, inputKeyingMaterial, inputKeyingMaterial.Length, salt, context);
            return hash;
        }
    }
}
