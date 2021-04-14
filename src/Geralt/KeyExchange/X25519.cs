using Geralt.Exceptions;

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
    /// <summary>Key exchange using X25519.</summary>
    public static class X25519
    {
        public const int KeySize = 32;
        public const int SharedSecretSize = 32;
        public const int SeedSize = 32;

        /// <summary>Generates a new key pair based on a random seed.</summary>
        /// <returns>A key pair.</returns>
        public static KeyPair GenerateKeyPair()
        {
            byte[] publicKey = new byte[KeySize];
            byte[] privateKey = new byte[KeySize];
            _ = LibsodiumLibrary.crypto_box_keypair(publicKey, privateKey);
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Generates a new key pair based on a private key.</summary>
        /// <param name="privateKey">The 32 byte private key.</param>
        /// <returns>A key pair.</returns>
        /// <exception cref="SeedOutOfRangeException"></exception>
        public static KeyPair GenerateKeyPair(byte[] privateKey)
        {
            ParameterValidation.PrivateKey(privateKey, KeySize);
            byte[] publicKey = GetPublicKey(privateKey);
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Generates a new key pair based on a seed.</summary>
        /// <param name="seed">The 32 byte seed.</param>
        /// <returns>A key pair.</returns>
        /// <exception cref="SeedOutOfRangeException"></exception>
        public static KeyPair GenerateSeededKeyPair(byte[] seed)
        {
            byte[] publicKey = new byte[KeySize];
            byte[] privateKey = new byte[KeySize];
            ParameterValidation.Seed(seed, SeedSize);
            _ = LibsodiumLibrary.crypto_box_seed_keypair(publicKey, privateKey, seed);
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Computes a public key from a private key.</summary>
        /// <param name="privateKey">The 32 byte private key.</param>
        /// <returns>The computed public key.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] GetPublicKey(byte[] privateKey)
        {
            ParameterValidation.PrivateKey(privateKey, KeySize);
            byte[] publicKey = new byte[KeySize];
            _ = LibsodiumLibrary.crypto_scalarmult_base(publicKey, privateKey);
            return publicKey;
        }

        /// <summary>Computes a shared secret from a private and public key.</summary>
        /// <param name="privateKey">The 32 byte private key.</param>
        /// <param name="publicKey">The 32 byte public key.</param>
        /// <returns>The computed shared secret.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] GetSharedSecret(byte[] privateKey, byte[] publicKey)
        {
            ParameterValidation.PrivateKey(privateKey, KeySize);
            ParameterValidation.PublicKey(publicKey, KeySize);
            byte[] sharedSecret = new byte[KeySize];
            _ = LibsodiumLibrary.crypto_scalarmult(sharedSecret, privateKey, publicKey);
            return sharedSecret;
        }
    }
}
