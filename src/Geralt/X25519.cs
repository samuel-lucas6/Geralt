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
    /// <summary>Scalar multiplication for Curve25519.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/advanced/scalar_multiplication </remarks>
    public static class X25519
    {
        private const int _keyBytes = 32;

        /// <summary>Compute a public key from a private key.</summary>
        /// <param name="privateKey">A private key.</param>
        /// <returns>The computed public key.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] GetPublicKey(byte[] privateKey)
        {
            ParameterValidation.PrivateKey(privateKey, _keyBytes);
            byte[] publicKey = new byte[_keyBytes];
            _ = LibsodiumLibrary.crypto_scalarmult_base(publicKey, privateKey);
            return publicKey;
        }

        /// <summary>Compute a shared secret from a private key and public key.</summary>
        /// <param name="privateKey">A private key.</param>
        /// <param name="publicKey">A public key.</param>
        /// <returns>The computed shared secret.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] GetSharedSecret(byte[] privateKey, byte[] publicKey)
        {
            ParameterValidation.PrivateKey(privateKey, _keyBytes);
            ParameterValidation.PublicKey(publicKey, _keyBytes);
            byte[] sharedSecret = new byte[_keyBytes];
            _ = LibsodiumLibrary.crypto_scalarmult(sharedSecret, privateKey, publicKey);
            return sharedSecret;
        }
    }
}
