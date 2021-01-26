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
    /// <summary>Scalar Multiplication</summary>
    public static class ScalarMult
    {
        private const int BYTES = 32;
        private const int SCALAR_BYTES = 32;

        //TODO: Add documentation header
        public static int Bytes()
        {
            return LibsodiumLibrary.crypto_scalarmult_bytes();
        }

        //TODO: Add documentation header
        public static int ScalarBytes()
        {
            return LibsodiumLibrary.crypto_scalarmult_scalarbytes();
        }

        //TODO: Add documentation header
        //TODO: Unit test(s)
        static byte Primitive()
        {
            return LibsodiumLibrary.crypto_scalarmult_primitive();
        }

        /// <summary>
        /// Diffie-Hellman (function computes the public key)
        /// </summary>
        /// <param name="secretKey">A secret key.</param>
        /// <returns>A computed public key.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Base(byte[] secretKey)
        {
            //validate the length of the scalar
            if (secretKey == null || secretKey.Length != SCALAR_BYTES)
                throw new KeyOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
                  string.Format("secretKey must be {0} bytes in length.", SCALAR_BYTES));

            var publicKey = new byte[SCALAR_BYTES];
            LibsodiumLibrary.crypto_scalarmult_base(publicKey, secretKey);

            return publicKey;
        }

        /// <summary>
        /// Diffie-Hellman (function computes a secret shared by the two keys) 
        /// </summary>
        /// <param name="secretKey">A secret key.</param>
        /// <param name="publicKey">A public key.</param>
        /// <returns>A computed secret shared.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Mult(byte[] secretKey, byte[] publicKey)
        {
            //validate the length of the scalar
            if (secretKey == null || secretKey.Length != SCALAR_BYTES)
                throw new KeyOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
                  string.Format("secretKey must be {0} bytes in length.", SCALAR_BYTES));

            //validate the length of the group element
            if (publicKey == null || publicKey.Length != BYTES)
                throw new KeyOutOfRangeException("publicKey", (publicKey == null) ? 0 : publicKey.Length,
                  string.Format("publicKey must be {0} bytes in length.", BYTES));

            var secretShared = new byte[BYTES];
            LibsodiumLibrary.crypto_scalarmult(secretShared, secretKey, publicKey);

            return secretShared;
        }
    }
}
