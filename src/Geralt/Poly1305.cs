using Geralt.Exceptions;
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
    /// <summary>Compute a message authentication code using Poly1305.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/advanced/poly1305 </remarks>
    public static class Poly1305
    {
        private const int _keyBytes = 32;
        private const int _tagBytes = 16;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>A byte array with 32 random bytes</returns>
        public static byte[] GenerateKey()
        {
            return SecureRandom.GetBytes(_keyBytes);
        }

        /// <summary>Computes the message authentication code of a message using Poly1305.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>A 16 byte authentication tag.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Compute(string message, byte[] key)
        {
            return Compute(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Computes the message authentication code of a message using Poly1305.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>A 16 byte authentication tag.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Compute(byte[] message, byte[] key)
        {
            ParameterValidation.Key(key, _keyBytes);
            byte[] tag = new byte[_tagBytes];
            _ = LibsodiumLibrary.crypto_onetimeauth(tag, message, message.Length, key);
            return tag;
        }

        /// <summary>Verifies a Poly1305 message authentication code.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The 16 byte authentication tag.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(string message, byte[] tag, byte[] key)
        {
            return Verify(Encoding.UTF8.GetBytes(message), tag, key);
        }

        /// <summary>Verifies a Poly1305 message authentication code.</summary>
        /// <param name="message">The message.</param>
        /// <param name="tag">The 16 byte authentication tag.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(byte[] message, byte[] tag, byte[] key)
        {
            ParameterValidation.Key(key, _keyBytes);
            ParameterValidation.Tag(tag, _tagBytes);
            int result = LibsodiumLibrary.crypto_onetimeauth_verify(tag, message, message.Length, key);
            return result == 0;
        }
    }
}
