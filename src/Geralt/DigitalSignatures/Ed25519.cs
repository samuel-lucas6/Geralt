using Geralt.Exceptions;
using System;
using System.Security.Cryptography;

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
    /// <summary>Digital signatures using Ed25519.</summary>
    public static class Ed25519
    {
        public const int PrivateKeySize = 64;
        public const int PublicKeySize = 32;
        public const int SignatureSize = 64;
        public const int SeedSize = 32;

        /// <summary>Creates a new key pair based on a random seed.</summary>
        /// <returns>A key pair.</returns>
        public static KeyPair GenerateKeyPair()
        {
            byte[] publicKey = new byte[PublicKeySize];
            byte[] privateKey = new byte[PrivateKeySize];
            _ = LibsodiumLibrary.crypto_sign_keypair(publicKey, privateKey);
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Creates a new key pair based on a seed.</summary>
        /// <param name="seed">The seed.</param>
        /// <returns>A key pair.</returns>
        /// <exception cref="SeedOutOfRangeException"></exception>
        public static KeyPair GenerateKeyPair(byte[] seed)
        {
            ParameterValidation.Seed(seed, SeedSize);
            byte[] publicKey = new byte[PublicKeySize];
            byte[] privateKey = new byte[PrivateKeySize];
            _ = LibsodiumLibrary.crypto_sign_seed_keypair(publicKey, privateKey, seed);
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Signs a message using Ed25519.</summary>
        /// <param name="message">The message.</param>
        /// <param name="privateKey">The 64 byte private key.</param>
        /// <returns>The message and signature.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(byte[] message, byte[] privateKey)
        {
            ParameterValidation.Message(message);
            ParameterValidation.PrivateKey(privateKey, PrivateKeySize);
            byte[] buffer = new byte[message.Length + SignatureSize];
            long signedMessageLength = 0;
            _ = LibsodiumLibrary.crypto_sign(buffer, ref signedMessageLength, message, message.Length, privateKey);
            byte[] signedMessage = new byte[signedMessageLength];
            Array.Copy(buffer, signedMessage, (int)signedMessageLength);
            return signedMessage;
        }

        /// <summary>Verifies a signed message.</summary>
        /// <param name="signedMessage">The signed message.</param>
        /// <param name="publicKey">The 32 byte public key.</param>
        /// <returns>The message without the signature.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Verify(byte[] signedMessage, byte[] publicKey)
        {
            ParameterValidation.Message(signedMessage);
            ParameterValidation.PublicKey(publicKey, PublicKeySize);
            byte[] buffer = new byte[signedMessage.Length];
            long messageLength = 0;
            int result = LibsodiumLibrary.crypto_sign_open(buffer, ref messageLength, signedMessage, signedMessage.Length, publicKey);
            if (result != 0)
            {
                throw new CryptographicException("Failed to verify signature.");
            }
            byte[] message = new byte[messageLength];
            Array.Copy(buffer, message, (int)messageLength);
            return message;
        }

        /// <summary>Creates a detached signature using Ed25519.</summary>
        /// <param name="message">The message.</param>
        /// <param name="privateKey">The 64 byte private key.</param>
        /// <returns>The signature.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignDetached(byte[] message, byte[] privateKey)
        {
            ParameterValidation.Message(message);
            ParameterValidation.PrivateKey(privateKey, PrivateKeySize);
            byte[] signature = new byte[SignatureSize];
            long signatureLength = 0;
            _ = LibsodiumLibrary.crypto_sign_detached(signature, ref signatureLength, message, message.Length, privateKey);
            return signature;
        }

        /// <summary>Verifies a detached signature.</summary>
        /// <param name="signature">The signature.</param>
        /// <param name="message">The message.</param>
        /// <param name="publicKey">The 32 byte public key.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static bool VerifyDetached(byte[] signature, byte[] message, byte[] publicKey)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Signature(signature, SignatureSize);
            ParameterValidation.PublicKey(publicKey, PublicKeySize);
            int result = LibsodiumLibrary.crypto_sign_verify_detached(signature, message, message.Length, publicKey);
            return result == 0;
        }

        /// <summary>Converts an Ed25519 public key to an X25519 public key.</summary>
        /// <param name="ed25519PublicKey">The 32 byte Ed25519 public key.</param>
        /// <returns>The 32 byte X25519 public key.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] ConvertPublicKeyToX25519(byte[] ed25519PublicKey)
        {
            ParameterValidation.PublicKey(ed25519PublicKey, PublicKeySize);
            byte[] x25519PublicKey = new byte[AuthenticatedHybridEncryption.PublicKeySize];
            int result = LibsodiumLibrary.crypto_sign_ed25519_pk_to_curve25519(x25519PublicKey, ed25519PublicKey);
            return result != 0 ? throw new CryptographicException("Failed to convert public key.") : x25519PublicKey;
        }

        /// <summary>Converts an Ed25519 private key to an X25519 private key.</summary>
        /// <param name="ed25519PrivateKey">The 64 byte Ed25519 private key.</param>
        /// <returns>The 32 byte X25519 private key.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] ConvertPrivateKeyToX25519(byte[] ed25519PrivateKey)
        {
            ParameterValidation.PrivateKey(ed25519PrivateKey, PrivateKeySize);
            byte[] x25519PrivateKey = new byte[AuthenticatedHybridEncryption.PrivateKeySize];
            int result = LibsodiumLibrary.crypto_sign_ed25519_sk_to_curve25519(x25519PrivateKey, ed25519PrivateKey);
            return result != 0 ? throw new CryptographicException("Failed to convert private key.") : x25519PrivateKey;
        }

        /// <summary>Extracts the seed from an Ed25519 private key.</summary>
        /// <param name="privateKey">The 64 byte Ed25519 private key.</param>
        /// <returns>The seed.</returns>
        public static byte[] ExtractSeed(byte[] privateKey)
        {
            ParameterValidation.PrivateKey(privateKey, PrivateKeySize);
            byte[] seed = new byte[SeedSize];
            int result = LibsodiumLibrary.crypto_sign_ed25519_sk_to_seed(seed, privateKey);
            return result != 0 ? throw new CryptographicException("Failed to extract the seed from the private key.") : seed;
        }

        /// <summary>Extracts the public key from an Ed25519 private key.</summary>
        /// <param name="privateKey">The 64 byte Ed25519 private key.</param>
        /// <returns>The public key.</returns>
        public static byte[] ExtractPublicKey(byte[] privateKey)
        {
            ParameterValidation.PrivateKey(privateKey, PrivateKeySize);
            byte[] publicKey = new byte[PublicKeySize];
            int result = LibsodiumLibrary.crypto_sign_ed25519_sk_to_pk(publicKey, privateKey);
            return result != 0 ? throw new CryptographicException("Failed to extract the public key from the private key.") : publicKey;
        }
    }
}
