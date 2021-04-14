using Geralt.Exceptions;
using System;
using System.Security.Cryptography;

/*
    ChaCha20-BLAKE2b: A committing AEAD implementation.
    Copyright (c) 2021 Samuel Lucas

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace Geralt
{
    /// <summary>Authenticated encryption with additional data using XChaCha20-BLAKE2b.</summary>
    public static class XChaCha20BLAKE2b
    {
        public const int KeySize = 32;
        public const int NonceSize = 24;
        public const int TagSize = 32;

        /// <summary>Encrypts a message using XChaCha20-BLAKE2b.</summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">Optional additional data to authenticate.</param>
        /// <returns>The encrypted message and authentication tag.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key, byte[] additionalData = null)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Nonce(nonce, NonceSize);
            ParameterValidation.Key(key, KeySize);
            additionalData = ParameterValidation.AdditionalData(additionalData);
            (byte[] encryptionKey, byte[] macKey) = ChaCha20BLAKE2bKeyDerivation.DeriveKeys(nonce, key);
            byte[] ciphertext = XChaCha20.Encrypt(message, nonce, encryptionKey);
            byte[] tagMessage = Arrays.Concat(additionalData, ciphertext, BitConversion.GetBytes(additionalData.Length), BitConversion.GetBytes(ciphertext.Length));
            byte[] tag = BLAKE2b.ComputeMAC(tagMessage, macKey, TagSize);
            return Arrays.Concat(ciphertext, tag);
        }

        /// <summary>Decrypts a ciphertext message using XChaCha20-BLAKE2b.</summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">Optional additional data to authenticate.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] key, byte[] additionalData = null)
        {
            ParameterValidation.Ciphertext(ciphertext);
            ParameterValidation.Nonce(nonce, NonceSize);
            ParameterValidation.Key(key, KeySize);
            additionalData = ParameterValidation.AdditionalData(additionalData);
            (byte[] encryptionKey, byte[] macKey) = ChaCha20BLAKE2bKeyDerivation.DeriveKeys(nonce, key);
            byte[] tag = Tag.Read(ciphertext, TagSize);
            ciphertext = Tag.Remove(ciphertext, TagSize);
            byte[] tagMessage = Arrays.Concat(additionalData, ciphertext, BitConversion.GetBytes(additionalData.Length), BitConversion.GetBytes(ciphertext.Length));
            byte[] computedTag = BLAKE2b.ComputeMAC(tagMessage, macKey, TagSize);
            bool validTag = ConstantTime.Compare(tag, computedTag);
            return !validTag ? throw new CryptographicException() : XChaCha20.Decrypt(ciphertext, nonce, encryptionKey);
        }
    }
}
