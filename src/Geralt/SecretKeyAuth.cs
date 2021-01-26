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
    /// <summary>Compute a message authentication code using HMAC.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/advanced/hmac-sha2 </remarks>
    public static class SecretKeyAuth
    {
        private const int KEY_BYTES = 32;
        private const int BYTES = 32;

        private const int CRYPTO_AUTH_HMACSHA256_KEY_BYTES = 32;
        private const int CRYPTO_AUTH_HMACSHA256_BYTES = 32;

        private const int CRYPTO_AUTH_HMACSHA512_KEY_BYTES = 32;
        private const int CRYPTO_AUTH_HMACSHA512_BYTES = 64;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>Returns a byte array with 32 random bytes</returns>
        public static byte[] GenerateKey()
        {
            return SecureRandom.GetBytes(KEY_BYTES);
        }

        /// <summary>Signs a message with HMAC-SHA512-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>32 byte authentication code.</returns>
        public static byte[] Sign(string message, byte[] key)
        {
            return Sign(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Signs a message with HMAC-SHA512-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>32 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(byte[] message, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEY_BYTES));

            var buffer = new byte[BYTES];
            LibsodiumLibrary.crypto_auth(buffer, message, message.Length, key);

            return buffer;
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 32 byte signature.</param>
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
        /// <param name="signature">The 32 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(byte[] message, byte[] signature, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEY_BYTES));

            //validate the length of the signature
            if (signature == null || signature.Length != BYTES)
                throw new SignatureOutOfRangeException("signature", (signature == null) ? 0 : signature.Length,
                  string.Format("signature must be {0} bytes in length.", BYTES));

            var ret = LibsodiumLibrary.crypto_auth_verify(signature, message, message.Length, key);

            return ret == 0;
        }

        /// <summary>Signs a message with HMAC-SHA-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>32 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignHmacSha256(byte[] message, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != CRYPTO_AUTH_HMACSHA256_KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA256_KEY_BYTES));

            var buffer = new byte[CRYPTO_AUTH_HMACSHA256_BYTES];
            LibsodiumLibrary.crypto_auth_hmacsha256(buffer, message, message.Length, key);

            return buffer;
        }

        /// <summary>Signs a message with HMAC-SHA-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>32 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignHmacSha256(string message, byte[] key)
        {
            return SignHmacSha256(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Signs a message with HMAC-SHA-512.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>64 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignHmacSha512(byte[] message, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != CRYPTO_AUTH_HMACSHA512_KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA512_KEY_BYTES));

            var buffer = new byte[CRYPTO_AUTH_HMACSHA512_BYTES];
            LibsodiumLibrary.crypto_auth_hmacsha512(buffer, message, message.Length, key);

            return buffer;
        }

        /// <summary>Signs a message with HMAC-SHA-512.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>64 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignHmacSha512(string message, byte[] key)
        {
            return SignHmacSha512(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Verifies a message signed with the SignHmacSha256 method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 32 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifyHmacSha256(string message, byte[] signature, byte[] key)
        {
            return VerifyHmacSha256(Encoding.UTF8.GetBytes(message), signature, key);
        }

        /// <summary>Verifies a message signed with the SignHmacSha256 method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 32 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifyHmacSha256(byte[] message, byte[] signature, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != CRYPTO_AUTH_HMACSHA256_KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA256_KEY_BYTES));

            //validate the length of the signature
            if (signature == null || signature.Length != CRYPTO_AUTH_HMACSHA256_BYTES)
                throw new SignatureOutOfRangeException("signature", (signature == null) ? 0 : signature.Length,
                  string.Format("signature must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA256_BYTES));

            var ret = LibsodiumLibrary.crypto_auth_hmacsha256_verify(signature, message, message.Length, key);

            return ret == 0;
        }

        /// <summary>Verifies a message signed with the SignHmacSha512 method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 64 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifyHmacSha512(string message, byte[] signature, byte[] key)
        {
            return VerifyHmacSha512(Encoding.UTF8.GetBytes(message), signature, key);
        }

        /// <summary>Verifies a message signed with the SignHmacSha512 method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 64 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifyHmacSha512(byte[] message, byte[] signature, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != CRYPTO_AUTH_HMACSHA512_KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA512_KEY_BYTES));

            //validate the length of the signature
            if (signature == null || signature.Length != CRYPTO_AUTH_HMACSHA512_BYTES)
                throw new SignatureOutOfRangeException("signature", (signature == null) ? 0 : signature.Length,
                  string.Format("signature must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA512_BYTES));

            var ret = LibsodiumLibrary.crypto_auth_hmacsha512_verify(signature, message, message.Length, key);

            return ret == 0;
        }
    }
}
