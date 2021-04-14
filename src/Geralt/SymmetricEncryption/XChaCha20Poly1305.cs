using Geralt.Exceptions;
using System;
using System.Runtime.InteropServices;
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
    /// <summary>Authenticated encryption with additional data using XChaCha20-Poly1305.</summary>
    public static class XChaCha20Poly1305
    {
        public const int KeySize = 32;
        public const int NonceSize = 24;
        public const int TagSize = 16;

        /// <summary>Encrypts a message using XChaCha20-Poly1305.</summary>
        /// <remarks>The nonce should never be reused with the same key. It must be incremented in constant time.</remarks>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">Optional, non-secret additional data to authenticate.</param>
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
            byte[] ciphertext = new byte[message.Length + TagSize];
            IntPtr ciphertextPointer = Marshal.AllocHGlobal(ciphertext.Length);
            int result = LibsodiumLibrary.crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertextPointer, out long ciphertextLength, message, message.Length, additionalData, additionalData.Length, nsec: null, nonce, key);
            Marshal.Copy(ciphertextPointer, ciphertext, startIndex: 0, (int)ciphertextLength);
            Marshal.FreeHGlobal(ciphertextPointer);
            ResultValidation.EncryptionResult(result);
            return ciphertext.Length == ciphertextLength ? ciphertext : NullPadding.RemoveTrailingNulls(ciphertext, ciphertextLength);
        }

        /// <summary>Decrypts a ciphertext message using XChaCha20-Poly1305.</summary>
        /// <param name="ciphertext">The ciphertext to be decrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">Optional, non-secret additional data to authenticate.</param>
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
            byte[] plaintext = new byte[ciphertext.Length - TagSize];
            IntPtr plaintextPointer = Marshal.AllocHGlobal(plaintext.Length);
            int result = LibsodiumLibrary.crypto_aead_xchacha20poly1305_ietf_decrypt(plaintextPointer, out long plaintextLength, nsec: null, ciphertext, ciphertext.Length, additionalData, additionalData.Length, nonce, key);
            Marshal.Copy(plaintextPointer, plaintext, startIndex: 0, (int)plaintextLength);
            Marshal.FreeHGlobal(plaintextPointer);
            ResultValidation.DecryptionResult(result);
            return plaintext.Length == plaintextLength ? plaintext : NullPadding.RemoveTrailingNulls(plaintext, plaintextLength);
        }
    }
}
