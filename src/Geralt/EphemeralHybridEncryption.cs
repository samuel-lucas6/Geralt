using Geralt.Exceptions;
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
    /// <summary>Send messages anonymously using an ephemeral key pair.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/public-key_cryptography/sealed_boxes </remarks>
    public static class EphemeralHybridEncryption
    {
        public const int _recipientPublicKeyBytes = 32;
        public const int _recipientPrivateKeyBytes = 32;
        private const int _ephemeralKeyAndTagBytes = 48;

        /// <summary>Anonymously encrypt a message that only the recipient can decrypt.</summary>
        /// <remarks>Warning: This function provides no authentication of the sender.</remarks>
        /// <param name="message">The message.</param>
        /// <param name="recipientKeyPair">The recipient's key pair (only uses the public key).</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(string message, KeyPair recipientKeyPair)
        {
            return Encrypt(Encoding.UTF8.GetBytes(message), recipientKeyPair.PublicKey);
        }

        /// <summary>Anonymously encrypt a message that only the recipient can decrypt.</summary>
        /// <remarks>Warning: This function provides no authentication of the sender.</remarks>
        /// <param name="message">The message.</param>
        /// <param name="recipientKeyPair">The recipient's key pair (only uses the public key).</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, KeyPair recipientKeyPair)
        {
            return Encrypt(message, recipientKeyPair.PublicKey);
        }

        /// <summary>Anonymously encrypt a message that only the recipient can decrypt.</summary>
        /// <remarks>Warning: This function provides no authentication of the sender.</remarks>
        /// <param name="message">The message.</param>
        /// <param name="recipientPublicKey">The 32 byte recipient public key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(string message, byte[] recipientPublicKey)
        {
            return Encrypt(Encoding.UTF8.GetBytes(message), recipientPublicKey);
        }

        /// <summary>Anonymously encrypt a message that only the recipient can decrypt.</summary>
        /// <remarks>Warning: This function provides no authentication of the sender.</remarks>
        /// <param name="message">The message.</param>
        /// <param name="recipientPublicKey">The 32 byte recipient public key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] recipientPublicKey)
        {
            ParameterValidation.PublicKey(recipientPublicKey, _recipientPublicKeyBytes);
            byte[] ciphertext = new byte[message.Length + _ephemeralKeyAndTagBytes];
            int result = LibsodiumLibrary.crypto_box_seal(ciphertext, message, message.Length, recipientPublicKey);
            ResultValidation.EncryptResult(result);
            return ciphertext;
        }

        /// <summary>Decrypt an anonymously encrypted message.</summary>
        /// <param name="ciphertext">The ciphertext to be decrypted.</param>
        /// <param name="recipientKeyPair">The recipient's key pair (only uses the public key).</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(string ciphertext, KeyPair recipientKeyPair)
        {
            return Decrypt(Utilities.HexToBinary(ciphertext), recipientKeyPair.PrivateKey, recipientKeyPair.PublicKey);
        }

        /// <summary>Decrypt an anonymously encrypted message.</summary>
        /// <param name="ciphertext">The ciphertext to be decrypted.</param>
        /// <param name="recipientKeyPair">The recipient's key pair (only uses the public key).</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] ciphertext, KeyPair recipientKeyPair)
        {
            return Decrypt(ciphertext, recipientKeyPair.PrivateKey, recipientKeyPair.PublicKey);
        }

        /// <summary>Decrypt an anonymously encrypted message.</summary>
        /// <param name="ciphertext">The ciphertext to be decrypted.</param>
        /// <param name="recipientPrivateKey">The recipient's private key.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(string ciphertext, byte[] recipientPrivateKey, byte[] recipientPublicKey)
        {
            return Decrypt(Utilities.HexToBinary(ciphertext), recipientPrivateKey, recipientPublicKey);
        }

        /// <summary>Decrypt an anonymously encrypted message.</summary>
        /// <param name="ciphertext">The ciphertext to be decrypted.</param>
        /// <param name="recipientPrivateKey">The recipient's private key.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] ciphertext, byte[] recipientPrivateKey, byte[] recipientPublicKey)
        {
            ParameterValidation.PrivateKey(recipientPrivateKey, _recipientPrivateKeyBytes);
            ParameterValidation.PublicKey(recipientPublicKey, _recipientPublicKeyBytes);
            byte[] message = new byte[ciphertext.Length - _ephemeralKeyAndTagBytes];
            int result = LibsodiumLibrary.crypto_box_seal_open(message, ciphertext, ciphertext.Length, recipientPublicKey, recipientPrivateKey);
            ResultValidation.DecryptResult(result);
            return  message;
        }
    }
}
