using Geralt.Exceptions;
using System;
using System.IO;

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
    internal static class ParameterValidation
    {
        internal static byte[] AdditionalData(byte[] additionalData)
        {
            // Additional data can be null
            return additionalData ?? (Array.Empty<byte>());
        }

        internal static void Nonce(byte[] nonce, int validNonceSize)
        {
            if (nonce == null || nonce.Length != validNonceSize)
            {
                throw new NonceOutOfRangeException(nameof(nonce), (nonce == null) ? 0 : nonce.Length, $"Nonce must be {validNonceSize} bytes in length.");
            }
        }

        internal static void Key(byte[] key, int validKeySize)
        {
            if (key == null || key.Length != validKeySize)
            {
                throw new KeyOutOfRangeException(nameof(key), (key == null) ? 0 : key.Length, $"Key must be {validKeySize} bytes in length.");
            }
        }

        internal static byte[] Key(byte[] key, int minKeySize, int maxKeySize)
        {
            return key != null && (key.Length < minKeySize || key.Length > maxKeySize) ? throw new KeyOutOfRangeException($"Key must be between {minKeySize} and {maxKeySize} bytes in length.") : key ?? Array.Empty<byte>();
        }

        internal static void PrivateKey(byte[] privateKey, int validPrivateKeySize)
        {
            if (privateKey == null || privateKey.Length != validPrivateKeySize)
            {
                throw new KeyOutOfRangeException(nameof(privateKey), (privateKey == null) ? 0 : privateKey.Length, $"Private key must be {validPrivateKeySize} bytes in length.");
            }
        }

        internal static void PublicKey(byte[] publicKey, int validPublicKeySize)
        {
            if (publicKey == null || publicKey.Length != validPublicKeySize)
            {
                throw new KeyOutOfRangeException(nameof(publicKey), (publicKey == null) ? 0 : publicKey.Length, $"Public key must be {validPublicKeySize} bytes in length.");
            }
        }

        internal static void Salt(byte[] salt, int validSaltSize)
        {
            if (salt == null || salt.Length != validSaltSize)
            {
                throw new SaltOutOfRangeException($"Salt must be {validSaltSize} bytes in length.");
            }
        }

        internal static void Context(byte[] context, int validContextSize)
        {
            if (context == null || context.Length != validContextSize)
            {
                throw new ContextOutOfRangeException($"Context must be {validContextSize} bytes in length.");
            }
        }

        internal static void Message(byte[] message)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message), "Message cannot be null.");
            }
        }

        internal static void Message(Stream message)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message), "Message cannot be null.");
            }
        }

        internal static void Ciphertext(byte[] ciphertext)
        {
            if (ciphertext == null)
            {
                throw new ArgumentNullException(nameof(ciphertext), "Ciphertext cannot be null.");
            }
        }

        internal static void Ciphertext(Stream ciphertext)
        {
            if (ciphertext == null)
            {
                throw new ArgumentNullException(nameof(ciphertext), "Ciphertext cannot be null.");
            }
        }

        internal static void OutputLength(int length, int minimumOutputLength, int maximumOutputLength)
        {
            if (length < minimumOutputLength || length > maximumOutputLength)
            {
                throw new LengthOutOfRangeException(nameof(length), length, $"Length must be between {minimumOutputLength} and {maximumOutputLength} bytes in length.");
            }
        }

        internal static void Tag(byte[] tag, int validTagSize)
        {
            if (tag == null || tag.Length != validTagSize)
            {
                throw new TagOutOfRangeException(nameof(tag), (tag == null) ? 0 : tag.Length, $"Tag must be {validTagSize} bytes in length.");
            }
        }

        internal static void Tag(byte[] tag, int minTagSize, int maxTagSize)
        {
            if (tag == null || tag.Length < minTagSize || tag.Length > maxTagSize)
            {
                throw new TagOutOfRangeException(nameof(tag), (tag == null) ? 0 : tag.Length, $"Tag must be between {minTagSize} and {maxTagSize} bytes in length.");
            }
        }

        internal static void TagLength(int length, int minimumOutputLength, int maximumOutputLength)
        {
            if (length < minimumOutputLength || length > maximumOutputLength)
            {
                throw new TagOutOfRangeException(nameof(length), length, $"Tag length must be between {minimumOutputLength} and {maximumOutputLength} bytes.");
            }
        }

        internal static void Signature(byte[] signature, int validSignatureSize)
        {
            if (signature == null || signature.Length != validSignatureSize)
            {
                throw new SignatureOutOfRangeException(nameof(signature), (signature == null) ? 0 : signature.Length, $"Signature must be {validSignatureSize} bytes in length.");
            }
        }

        internal static void Seed(byte[] seed, int validSeedSize)
        {
            if (seed == null || seed.Length != validSeedSize)
            {
                throw new SeedOutOfRangeException(nameof(seed), (seed == null) ? 0 : seed.Length, $"Seed must be {validSeedSize} bytes in length.");
            }
        }

        internal static void Password(byte[] password)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password), "Password cannot be null.");
            }
        }

        internal static void Hash(byte[] hash)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash), "Hash cannot be null");
            }
        }

        internal static void Iterations(int iterations, int minimumArgon2idIterations, int minimumArgon2iIterations, Argon2.Algorithm algorithm)
        {
            if (algorithm == Argon2.Algorithm.Argon2id && iterations < minimumArgon2idIterations)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations), $"Iterations must be at least {minimumArgon2idIterations}.");
            }
            else if (algorithm == Argon2.Algorithm.Argon2i && iterations < minimumArgon2iIterations)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations), $"Iterations must be at least {minimumArgon2iIterations} because there are attacks on Argon2i.");
            }
        }

        internal static void MemorySize(int memorySize)
        {
            if (memorySize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(memorySize), "Memory size cannot be zero or negative.");
            }
        }

        internal static void OutputLength(int outputLength)
        {
            if (outputLength <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length cannot be zero or negative.");
            }
        }
    }
}
