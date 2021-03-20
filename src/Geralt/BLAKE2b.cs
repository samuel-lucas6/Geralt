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
    /// <remarks>See here for more information: https://doc.libsodium.org/hashing/generic_hashing </remarks>
    public partial class BLAKE2b
    {
        public const int KeySize = 32;
        public const int SaltSize = 16;
        public const int PersonalSize = 16;
        public const int Length = 64;
        private const int _minOutputlength = 16;
        private const int _maxOutputlength = 64;
        private const int _minKeylength = 16;
        private const int _maxKeylength = 64;

        public static byte[] Hash(string message, int length = Length)
        {
            return MAC(Encoding.UTF8.GetBytes(message), key: null, length);
        }

        public static byte[] Hash(byte[] message, int length = Length)
        {
            return MAC(message, key: null, length);
        }

        /// <summary>Hashes a message with an optional key using BLAKE2b.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key - may be null; otherwise, between 16 and 64 length.</param>
        /// <param name="length">The size (in length) of the desired output.</param>
        /// <returns>A byte array of the specified length.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] MAC(string message, byte[] key, int length = Length)
        {
            return MAC(Encoding.UTF8.GetBytes(message), key, length);
        }

        /// <summary>Hashes a message with an optional key using BLAKE2b.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key - may be null; otherwise, between 16 and 64 length.</param>
        /// <param name="length">The size (in length) of the desired output.</param>
        /// <returns>A byte array of the specified length.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] MAC(byte[] message, byte[] key, int length = Length)
        {
            key = ParameterValidation.Key(key, _minKeylength, _maxKeylength);
            ParameterValidation.OutputLength(length, _minOutputlength, _maxOutputlength);
            byte[] hash = new byte[length];
            _ = LibsodiumLibrary.crypto_generichash(hash, hash.Length, message, message.Length, key, key.Length);
            return hash;
        }

        /// <summary>Derives a subkey based on a master key, salt, and personalisation parameter.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key for keyed hashing.</param>
        /// <param name="salt">The salt for key derivation.</param>
        /// <param name="personal">The personalisation parameter for key derivation.</param>
        /// <param name="length">The size (in length) of the desired output.</param>
        /// <returns>The derived subkey message.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="PersonalOutOfRangeException"></exception>
        public static byte[] DeriveKey(byte[] message, byte[] key, byte[] salt, byte[] personal, int length = KeySize)
        {
            ParameterValidation.Message(message);
            key = ParameterValidation.Key(key, _minKeylength, _maxKeylength);
            ParameterValidation.Salt(salt, SaltSize);
            ParameterValidation.Personal(personal, PersonalSize);
            ParameterValidation.OutputLength(length, _minOutputlength, _maxOutputlength);
            byte[] hash = new byte[length];
            _ = LibsodiumLibrary.crypto_generichash_blake2b_salt_personal(hash, hash.Length, message, message.Length, key, key.Length, salt, personal);
            return hash;
        }
    }
}
