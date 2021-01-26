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
    /// <summary>One Time Message Authentication</summary>
    public static class Poly1305
    {
        private const int _keyBytes = 32;
        private const int _tagBytes = 16;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>Returns a byte array with 32 random bytes</returns>
        public static byte[] GenerateKey()
        {
            return GeraltCore.GetRandomBytes(_keyBytes);
        }

        /// <summary>Signs a message using Poly1305.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>A 16 byte authentication tag.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(string message, byte[] key)
        {
            return Sign(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Signs a message using Poly1305.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>A 16 byte authentication tag.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(byte[] message, byte[] key)
        {
            if (key == null || key.Length != _keyBytes)
            {
                throw new KeyOutOfRangeException(nameof(key), (key == null) ? 0 : key.Length, $"Key must be {_keyBytes} bytes in length.");
            }
            byte[] authenticationTag = new byte[_tagBytes];
            _ = LibsodiumLibrary.crypto_onetimeauth(authenticationTag, message, message.Length, key);
            return authenticationTag;
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 16 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(string message, byte[] signature, byte[] key)
        {
            return Verify(Encoding.UTF8.GetBytes(message), signature, key);
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 16 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(byte[] message, byte[] signature, byte[] key)
        {
            if (key == null || key.Length != _keyBytes)
            {
                throw new KeyOutOfRangeException(nameof(key), (key == null) ? 0 : key.Length, $"Key must be {_keyBytes} bytes in length.");
            }
            if (signature == null || signature.Length != _tagBytes)
            {
                throw new SignatureOutOfRangeException(nameof(signature), (signature == null) ? 0 : signature.Length, $"Signature must be {_tagBytes} bytes in length.");
            }
            int result = LibsodiumLibrary.crypto_onetimeauth_verify(signature, message, message.Length, key);
            return result == 0;
        }
    }
}
