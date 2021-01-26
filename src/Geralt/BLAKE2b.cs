using System;
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
    /// <summary>Hashing, keyed hashing, and key derivation using BLAKE2b.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/hashing/generic_hashing </remarks>
    public partial class BLAKE2b
    {
        private const int _minOutputBytes = 16;
        private const int _maxOutputBytes = 64;
        private const int _defaultOutputBytes = 64;
        private const int _minKeyBytes = 16;
        private const int _maxKeyBytes = 64;
        private const int _saltBytes = 16;
        private const int _personalBytes = 16;

        /// <summary>Generates a random 64 byte key.</summary>
        /// <returns>A byte array with 64 random bytes.</returns>
        public static byte[] GenerateKey()
        {
            return GeraltCore.GetRandomBytes(_maxKeyBytes);
        }

        /// <summary>Hashes a message with an optional key using BLAKE2b.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key - may be null; otherwise, between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired output.</param>
        /// <returns>A byte array of the specified length.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(string message, string key, int bytes)
        {
            return Hash(message, Encoding.UTF8.GetBytes(key), bytes);
        }

        /// <summary>Hashes a message with an optional key using BLAKE2b.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key - may be null; otherwise, between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired output.</param>
        /// <returns>A byte array of the specified length.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(string message, byte[] key, int bytes)
        {
            return Hash(Encoding.UTF8.GetBytes(message), key, bytes);
        }

        /// <summary>Hashes a message with an optional key using BLAKE2b.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key - may be null; otherwise, between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired output.</param>
        /// <returns>A byte array of the specified length.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(byte[] message, byte[] key, int bytes)
        {
            key = ParameterValidation.Key(key);
            ParameterValidation.Key(key, _minKeyBytes, _maxKeyBytes);
            ParameterValidation.OutputLength(bytes, _minOutputBytes, _maxOutputBytes);
            byte[] hash = new byte[bytes];
            _ = LibsodiumLibrary.crypto_generichash(hash, hash.Length, message, message.Length, key, key.Length);
            return hash;
        }

        /// <summary>Generates a hash based on a key, salt, and personalisation parameter.</summary>
        /// <remarks>Can be used for key derivation as an alternative to HKDF.</remarks>
        /// <returns>The hashed message.</returns>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key for keyed hashing.</param>
        /// <param name="salt">The salt for key derivation.</param>
        /// <param name="personal">The personalisation parameter for key derivation.</param>
        /// <param name="bytes">The size (in bytes) of the desired output.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="PersonalOutOfRangeException"></exception>
        public static byte[] HashSaltPersonal(string message, string key, string salt, string personal, int bytes = _defaultOutputBytes)
        {
            return HashSaltPersonal(Encoding.UTF8.GetBytes(message), Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(salt), Encoding.UTF8.GetBytes(personal), bytes);
        }

        /// <summary>Generates a hash based on a key, salt, and personalisation parameter.</summary>
        /// <remarks>Can be used for key derivation as an alternative to HKDF.</remarks>
        /// <returns>The hashed message.</returns>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key for keyed hashing.</param>
        /// <param name="salt">The salt for key derivation.</param>
        /// <param name="personal">The personalisation parameter for key derivation.</param>
        /// <param name="bytes">The size (in bytes) of the desired output.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="PersonalOutOfRangeException"></exception>
        public static byte[] HashSaltPersonal(byte[] message, byte[] key, byte[] salt, byte[] personal, int bytes = _defaultOutputBytes)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Salt(salt, _saltBytes);
            ParameterValidation.Personal(personal, _personalBytes);
            key = ParameterValidation.Key(key);
            ParameterValidation.Key(key, _minKeyBytes, _maxKeyBytes);
            ParameterValidation.OutputLength(bytes, _minOutputBytes, _maxOutputBytes);
            byte[] hash = new byte[bytes];
            _ = LibsodiumLibrary.crypto_generichash_blake2b_salt_personal(hash, hash.Length, message, message.Length, key, key.Length, salt, personal);
            return hash;
        }
    }
}
