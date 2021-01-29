using Geralt.Exceptions;
using System;
using System.Security.Cryptography;
using System.Text;

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
    /// <summary>Authenticated hybrid encryption.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/public-key_cryptography/authenticated_encryption </remarks>
    public static class AuthenticatedHybridEncryption
    {
        public const int _publicKeyBytes = 32;
        public const int _privateKeyBytes = 32;
        private const int _nonceBytes = 24;
        private const int _tagBytes = 16;

        /// <summary>Generates a new key pair based on a random seed.</summary>
        /// <returns>A key pair.</returns>
        public static KeyPair GenerateKeyPair()
        {
            byte[] publicKey = new byte[_publicKeyBytes];
            byte[] privateKey = new byte[_privateKeyBytes];
            _ = LibsodiumLibrary.crypto_box_keypair(publicKey, privateKey);
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Generates a new key pair based on the specified private key.</summary>
        /// <param name="privateKey">The 32 byte private key.</param>
        /// <returns>A key pair.</returns>
        /// <exception cref="SeedOutOfRangeException"></exception>
        public static KeyPair GenerateKeyPair(byte[] privateKey)
        {
            ParameterValidation.PrivateKey(privateKey, _privateKeyBytes);
            byte[] publicKey = X25519.GetPublicKey(privateKey);
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Generates a new key pair based on the provided seed.</summary>
        /// <param name="seed">The 32 byte seed.</param>
        /// <returns>A key pair.</returns>
        /// <exception cref="SeedOutOfRangeException"></exception>
        public static KeyPair GenerateSeededKeyPair(byte[] seed)
        {
            byte[] publicKey = new byte[_publicKeyBytes];
            byte[] privateKey = new byte[_privateKeyBytes];
            // Expected length of the seed
            int seedBytes = LibsodiumLibrary.crypto_box_seedbytes();
            ParameterValidation.Seed(seed, seedBytes);
            _ = LibsodiumLibrary.crypto_box_seed_keypair(publicKey, privateKey, seed);
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Generates a random 24 byte nonce.</summary>
        /// <returns>A byte array with 24 random bytes.</returns>
        public static byte[] GenerateNonce()
        {
            return SecureRandom.GetBytes(_nonceBytes);
        }

        /// <summary>Encrypts a message that the sender and recipient can decrypt.</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="senderPrivateKey">The sender's private key.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(string message, byte[] nonce, byte[] senderPrivateKey, byte[] recipientPublicKey)
        {
            return Encrypt(Encoding.UTF8.GetBytes(message), nonce, senderPrivateKey, recipientPublicKey);
        }

        /// <summary>Encrypts a message that the sender and recipient can decrypt.</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="senderPrivateKey">The sender's private key.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] senderPrivateKey, byte[] recipientPublicKey)
        {
            ParameterValidation.Nonce(nonce, _nonceBytes);
            ParameterValidation.PrivateKey(senderPrivateKey, _privateKeyBytes);
            ParameterValidation.PublicKey(recipientPublicKey, _publicKeyBytes);
            byte[] ciphertext = new byte[message.Length + _tagBytes];
            int result = LibsodiumLibrary.crypto_box_easy(ciphertext, message, message.Length, nonce, recipientPublicKey, senderPrivateKey);
            return result != 0 ? throw new CryptographicException("Error encrypting message.") : ciphertext;
        }

        /// <summary>Decrypts a message from the sender.</summary>
        /// <param name="ciphertext">The ciphertext to be decrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="recipientPrivateKey">The recipient's private key.</param>
        /// <param name="senderPublicKey">The sender's public key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] recipientPrivateKey, byte[] senderPublicKey)
        {
            ParameterValidation.Nonce(nonce, _nonceBytes);
            ParameterValidation.PrivateKey(recipientPrivateKey, _privateKeyBytes);
            ParameterValidation.PublicKey(senderPublicKey, _publicKeyBytes);
            ciphertext = NullPadding.TrimLeadingNulls(ciphertext, _tagBytes);
            byte[] message = new byte[ciphertext.Length - _tagBytes];
            int result = LibsodiumLibrary.crypto_box_open_easy(message, ciphertext, ciphertext.Length, nonce, senderPublicKey, recipientPrivateKey);
            return result != 0 ? throw new CryptographicException("Error decrypting message.") : message;
        }
    }
}
