using System;
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
    public static class ParameterValidation
    {
        public static byte[] AdditionalData(byte[] additionalData)
        {
            // Additional data can be null
            return additionalData ?? (Array.Empty<byte>());
        }

        public static void Nonce(byte[] nonce, int validNonceLength)
        {
            if (nonce == null || nonce.Length != validNonceLength)
            {
                throw new NonceOutOfRangeException(nameof(nonce), (nonce == null) ? 0 : nonce.Length, $"Nonce must be {validNonceLength} bytes in length.");
            }
        }

        public static void Key(byte[] key, int validKeyLength)
        {
            if (key == null || key.Length != validKeyLength)
            {
                throw new KeyOutOfRangeException(nameof(key), (key == null) ? 0 : key.Length, $"Key must be {validKeyLength} bytes in length.");
            }
        }

        public static byte[] Key(byte[] key, int minimumKeyLength, int maxKeyLength)
        {
            if (key != null && (key.Length < minimumKeyLength || key.Length > maxKeyLength))
            {
                throw new KeyOutOfRangeException($"Key must be between {minimumKeyLength} and {maxKeyLength} bytes in length.");
            }
            return key ?? Array.Empty<byte>();
        }

        public static void PrivateKey(byte[] privateKey, int validPrivateKeyLength)
        {
            if (privateKey == null || privateKey.Length != validPrivateKeyLength)
            {
                throw new KeyOutOfRangeException(nameof(privateKey), (privateKey == null) ? 0 : privateKey.Length, $"Private key must be {validPrivateKeyLength} bytes in length.");
            }
        }

        public static void PublicKey(byte[] publicKey, int validPublicKeyLength)
        {
            if (publicKey == null || publicKey.Length != validPublicKeyLength)
            {
                throw new KeyOutOfRangeException(nameof(publicKey), (publicKey == null) ? 0 : publicKey.Length, $"Public key must be {validPublicKeyLength} bytes in length.");
            }
        }

        public static void Salt(byte[] salt, int validSaltLength)
        {
            if (salt == null || salt.Length != validSaltLength)
            {
                throw new SaltOutOfRangeException($"Salt must be {validSaltLength} bytes in length.");
            }
        }

        public static void Personal(byte[] personal, int validPersonalLength)
        {
            if (personal == null || personal.Length != validPersonalLength)
            {
                throw new PersonalOutOfRangeException($"Personal must be {validPersonalLength} bytes in length.");
            }
        }

        public static void Message(byte[] message)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message), "Message cannot be null.");
            }
        }

        public static void OutputLength(int bytes, int minimumOutputBytes, int maximumOutputBytes)
        {
            if (bytes < minimumOutputBytes || bytes > maximumOutputBytes)
            {
                throw new BytesOutOfRangeException(nameof(bytes), bytes, $"Bytes must be between {minimumOutputBytes} and {maximumOutputBytes} bytes in length.");
            }
        }

        public static void OutputLength(int outputLength, int minimumOutputLength)
        {
            if (outputLength < minimumOutputLength)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), $"Output length cannot be less than {minimumOutputLength} bytes.");
            }
        }

        public static void Signature(byte[] signature, int validSignatureLength)
        {
            if (signature == null || signature.Length != validSignatureLength)
            {
                throw new SignatureOutOfRangeException(nameof(signature), (signature == null) ? 0 : signature.Length, $"Signature must be {validSignatureLength} bytes in length.");
            }
        }

        public static void Password(byte[] password)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password), "Password cannot be null.");
            }
        }

        public static void Password(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password), "Password cannot be null");
            }
        }

        public static void Hash(byte[] hash)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash), "Hash cannot be null");
            }
        }

        public static void PasswordHashingResult(int result)
        {
            if (result != 0)
            {
                throw new OutOfMemoryException("Internal error - hashing failed. Possibly not enough memory.");
            }
        }

        public static void Seed(byte[] seed, int validSeedLength)
        {
            if (seed == null || seed.Length != validSeedLength)
            {
                throw new SeedOutOfRangeException(nameof(seed), (seed == null) ? 0 : seed.Length, $"Seed must be {validSeedLength} bytes in length.");
            }
        }
    }
}
