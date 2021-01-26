using System.Security.Cryptography;
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
    /// <summary> Create and Open SealedPublicKeyBoxes. </summary>
    public static class SealedPublicKeyBox
    {
        public const int RecipientPublicKeyBytes = 32;
        public const int RecipientSecretKeyBytes = 32;
        private const int CryptoBoxSealbytes = 48;

        /// <summary> Creates a SealedPublicKeyBox</summary>
        /// <param name="message">The message.</param>
        /// <param name="recipientKeyPair">The recipientKeyPair key pair (uses only the public key).</param>
        /// <returns>The anonymously encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Create(string message, KeyPair recipientKeyPair)
        {
            return Create(Encoding.UTF8.GetBytes(message), recipientKeyPair.PublicKey);
        }

        /// <summary> Creates a SealedPublicKeyBox</summary>
        /// <param name="message">The message.</param>
        /// <param name="recipientKeyPair">The recipientKeyPair key pair (uses only the public key).</param>
        /// <returns>The anonymously encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Create(byte[] message, KeyPair recipientKeyPair)
        {
            return Create(message, recipientKeyPair.PublicKey);
        }

        /// <summary> Creates a SealedPublicKeyBox</summary>
        /// <param name="message">The message.</param>
        /// <param name="recipientPublicKey">The 32 byte recipient's public key.</param>
        /// <returns>The anonymously encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Create(string message, byte[] recipientPublicKey)
        {
            return Create(Encoding.UTF8.GetBytes(message), recipientPublicKey);
        }

        /// <summary> Creates a SealedPublicKeyBox</summary>
        /// <param name="message">The message.</param>
        /// <param name="recipientPublicKey">The 32 byte recipient's public key.</param>
        /// <returns>The anonymously encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Create(byte[] message, byte[] recipientPublicKey)
        {
            //validate the length of the recipient public key
            if (recipientPublicKey == null || recipientPublicKey.Length != RecipientPublicKeyBytes)
                throw new KeyOutOfRangeException("recipientPublicKey",
                    (recipientPublicKey == null) ? 0 : recipientPublicKey.Length,
                    string.Format("recipientPublicKey must be {0} bytes in length.", RecipientPublicKeyBytes));

            var buffer = new byte[message.Length + CryptoBoxSealbytes];
            var ret = LibsodiumLibrary.crypto_box_seal(buffer, message, message.Length, recipientPublicKey);

            if (ret != 0)
                throw new CryptographicException("Failed to create SealedBox");

            return buffer;
        }

        /// <summary>Opens a SealedPublicKeyBox</summary>
        /// <param name="cipherText">Hex-encoded cipherText to be opened.</param>
        /// <param name="recipientKeyPair">The recipient's key pair.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Open(string cipherText, KeyPair recipientKeyPair)
        {
            return Open(Utilities.HexToBinary(cipherText), recipientKeyPair.PrivateKey, recipientKeyPair.PublicKey);
        }

        /// <summary>Opens a SealedPublicKeyBox</summary>
        /// <param name="cipherText">The cipherText to be opened.</param>
        /// <param name="recipientKeyPair">The recipient's key pair.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Open(byte[] cipherText, KeyPair recipientKeyPair)
        {
            return Open(cipherText, recipientKeyPair.PrivateKey, recipientKeyPair.PublicKey);
        }

        /// <summary>Opens a SealedPublicKeyBox</summary>
        /// <param name="cipherText">Hex-encoded cipherText to be opened.</param>
        /// <param name="recipientSecretKey">The recipient's secret key.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Open(string cipherText, byte[] recipientSecretKey, byte[] recipientPublicKey)
        {
            return Open(Utilities.HexToBinary(cipherText), recipientSecretKey, recipientPublicKey);
        }

        /// <summary>Opens a SealedPublicKeyBox</summary>
        /// <param name="cipherText">The cipherText to be opened.</param>
        /// <param name="recipientSecretKey">The recipient's secret key.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Open(byte[] cipherText, byte[] recipientSecretKey, byte[] recipientPublicKey)
        {
            //validate the length of the recipient secret key
            if (recipientSecretKey == null || recipientSecretKey.Length != RecipientSecretKeyBytes)
                throw new KeyOutOfRangeException("recipientPublicKey",
                    (recipientSecretKey == null) ? 0 : recipientSecretKey.Length,
                    string.Format("recipientSecretKey must be {0} bytes in length.", RecipientSecretKeyBytes));

            //validate the length of the recipient public key
            if (recipientPublicKey == null || recipientPublicKey.Length != RecipientPublicKeyBytes)
                throw new KeyOutOfRangeException("recipientPublicKey",
                    (recipientPublicKey == null) ? 0 : recipientPublicKey.Length,
                    string.Format("recipientPublicKey must be {0} bytes in length.", RecipientPublicKeyBytes));


            var buffer = new byte[cipherText.Length - CryptoBoxSealbytes];
            var ret = LibsodiumLibrary.crypto_box_seal_open(buffer, cipherText, cipherText.Length, recipientPublicKey,
                recipientSecretKey);

            if (ret != 0)
                throw new CryptographicException("Failed to open SealedBox");

            return buffer;
        }
    }
}
