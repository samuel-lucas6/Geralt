using Geralt.Exceptions;
using System;
using System.IO;
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
    /// <summary>Key derivation using BLAKE2b.</summary>
    public partial class BLAKE2b
    {
        public const int SaltSize = 16;
        public const int ContextSize = 16;
        private const int _keySize = 32;
        private const int _hashSize = 64;
        private const int _macSize = 32;
        private const int _minHashSize = 16;
        private const int _maxHashSize = 64;
        private const int _minKeySize = 16;
        private const int _maxKeySize = 64;

        /// <summary>Derives a subkey from a high-entropy master key.</summary>
        /// <remarks>The subkey length should be 32 or 64 bytes.</remarks>
        /// <param name="inputKeyingMaterial">The high-entropy master key.</param>
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
        public static byte[] DeriveKey(byte[] inputKeyingMaterial, byte[] salt, string context, int length = _keySize, byte[] message = null)
        {
            return DeriveKey(inputKeyingMaterial, salt, Encoding.UTF8.GetBytes(context), length, message);
        }

        /// <summary>Derives a subkey from a high-entropy master key.</summary>
        /// <remarks>The subkey length should be 32 or 64 bytes.</remarks>
        /// <param name="inputKeyingMaterial">The high-entropy master key.</param>
        /// <param name="salt">The 16 byte random or counter salt.</param>
        /// <param name="context">The 16 byte context information.</param>
        /// <param name="length">The subkey size in bytes.</param>
        /// <param name="message">An optional message to be included in the hash.</param>
        /// <returns>The derived subkey.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="ContextOutOfRangeException"></exception>
        /// <exception cref="LengthOutOfRangeException"></exception>
        public static byte[] DeriveKey(byte[] inputKeyingMaterial, byte[] salt, byte[] context, int length = _keySize, byte[] message = null)
        {
            inputKeyingMaterial = ParameterValidation.Key(inputKeyingMaterial, _minKeySize, _maxKeySize);
            ParameterValidation.Salt(salt, SaltSize);
            ParameterValidation.Context(context, ContextSize);
            ParameterValidation.OutputLength(length, _minHashSize, _maxHashSize);
            if (message == null) { message = Array.Empty<byte>(); }
            byte[] hash = new byte[length];
            _ = LibsodiumLibrary.crypto_generichash_blake2b_salt_personal(hash, hash.Length, message, message.Length, inputKeyingMaterial, inputKeyingMaterial.Length, salt, context);
            return hash;
        }

        /// <summary>Hashes a message using BLAKE2b.</summary>
        /// <remarks>The output length should be 32 or 64 bytes.</remarks>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="length">The length of the hash in bytes.</param>
        /// <returns>The hash of the message.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="LengthOutOfRangeException"></exception>
        internal static byte[] ComputeHash(byte[] message, int length = _hashSize)
        {
            return ComputeMAC(message, key: null, length);
        }

        /// <summary>Hashes a message using BLAKE2b.</summary>
        /// <remarks>The output length should be 32 or 64 bytes.</remarks>
        /// <param name="message">The message to be hashed.</param>
        /// <returns>The hash of the message.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        internal static byte[] ComputeHash(Stream message, int length = _hashSize)
        {
            using var blake2b = new BLAKE2bStream(length);
            return blake2b.ComputeHash(message);
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
        internal static byte[] ComputeMAC(byte[] message, byte[] key, int length = _macSize)
        {
            ParameterValidation.Message(message);
            key = ParameterValidation.Key(key, _minKeySize, _maxKeySize);
            ParameterValidation.OutputLength(length, _minHashSize, _maxHashSize);
            byte[] hash = new byte[length];
            _ = LibsodiumLibrary.crypto_generichash(hash, hash.Length, message, message.Length, key, key.Length);
            return hash;
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
        internal static byte[] ComputeMAC(Stream message, byte[] key, int length = _macSize)
        {
            ParameterValidation.Message(message);
            key = ParameterValidation.Key(key, _minKeySize, _maxKeySize);
            ParameterValidation.OutputLength(length, _minHashSize, _maxHashSize);
            using var blake2b = new BLAKE2bStream(key, length);
            return blake2b.ComputeHash(message);
        }

        /// <summary>Verifies a BLAKE2b authentication tag.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The authentication tag.</param>
        /// <param name="key">The key.</param>
        /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="TagOutOfRangeException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        internal static bool VerifyMAC(byte[] message, byte[] tag, byte[] key)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Tag(tag, _minHashSize, _maxHashSize);
            ParameterValidation.Key(key, _keySize);
            byte[] computedTag = ComputeMAC(message, key, tag.Length);
            return ConstantTime.Compare(tag, computedTag);
        }

        /// <summary>Verifies a BLAKE2b authentication tag appended to the message.</summary>
        /// <param name="message">The message and authentication tag.</param>
        /// <param name="key">The key.</param>
        /// <param name="tagLength">The authentication tag length.</param>
        /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="TagOutOfRangeException"></exception>
        internal static bool VerifyMAC(byte[] message, byte[] key, int tagLength = _macSize)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Key(key, _keySize);
            ParameterValidation.TagLength(tagLength, _minHashSize, _maxHashSize);
            byte[] tag = new byte[tagLength];
            Array.Copy(message, sourceIndex: message.Length - tag.Length, tag, destinationIndex: 0, tag.Length);
            byte[] computedTag = ComputeMAC(message, key, tagLength);
            return ConstantTime.Compare(tag, computedTag);
        }

        /// <summary>Verifies a BLAKE2b authentication tag appended to the message.</summary>
        /// <param name="message">The message and authentication tag.</param>
        /// <param name="key">The key.</param>
        /// <param name="tagLength">The authentication tag length.</param>
        /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="TagOutOfRangeException"></exception>
        internal static bool VerifyMAC(Stream message, byte[] key, int tagLength = _macSize)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Key(key, _keySize);
            ParameterValidation.TagLength(tagLength, _minHashSize, _maxHashSize);
            message.Seek(-tagLength, SeekOrigin.End);
            byte[] tag = new byte[tagLength];
            message.Read(tag, offset: 0, tag.Length);
            message.Seek(offset: 0, SeekOrigin.Begin);
            using var blake2 = new BLAKE2bStream(key, tagLength);
            byte[] computedTag = blake2.ComputeHash(message);
            return ConstantTime.Compare(tag, computedTag);
        }
    }
}
