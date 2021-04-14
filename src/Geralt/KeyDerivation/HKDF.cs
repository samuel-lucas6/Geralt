using System;
using System.Security.Cryptography;

/*
    HKDF.NET: A .NET implementation of HKDF.
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
    /// <summary>Key derivation using HKDF.</summary>
    internal static class HKDF
    {
        public const int SaltSize = 32;
        private const int _defaultOutputLength = 32;

        /// <summary>Derives a subkey from a master key.</summary>
        /// <param name="hashAlgorithmName">The SHA2 hash algorithm.</param>
        /// <param name="inputKeyingMaterial">The master key.</param>
        /// <param name="outputLength">The length of the output keying material.</param>
        /// <param name="salt">An optional, random salt.</param>
        /// <param name="info">Optional context information.</param>
        /// <returns>The output keying material.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        internal static byte[] DeriveKey(HashAlgorithmName hashAlgorithmName, byte[] inputKeyingMaterial, int outputLength = _defaultOutputLength, byte[] salt = null, byte[] info = null)
        {
            byte[] key = Extract(hashAlgorithmName, inputKeyingMaterial, salt);
            return Expand(hashAlgorithmName, key, outputLength, info);
        }

        /// <summary>Generates a pseudorandom key for use with <see cref="Expand"/>.</summary>
        /// <param name="hashAlgorithmName">The SHA2 hash algorithm.</param>
        /// <param name="inputKeyingMaterial">The input secret.</param>
        /// <param name="salt">An optional, random salt.</param>
        /// <returns>A pseudorandom key of the specified output length.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        internal static byte[] Extract(HashAlgorithmName hashAlgorithmName, byte[] inputKeyingMaterial, byte[] salt = null)
        {
            if (inputKeyingMaterial == null) { throw new ArgumentNullException(nameof(inputKeyingMaterial), "Input keying material cannot be null."); }
            if (salt == null) { salt = Array.Empty<byte>(); }
            using var hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, salt);
            hmac.AppendData(inputKeyingMaterial);
            return hmac.GetHashAndReset();
        }

        /// <summary>Expands a pseudorandom key generated using <see cref="Extract"/>.</summary>
        /// <param name="hashAlgorithmName">The SHA2 hash algorithm.</param>
        /// <param name="key">The pseudorandom key.</param>
        /// <param name="outputLength">The length of the output keying material.</param>
        /// <param name="info">Optional context information.</param>        
        /// <returns>The output keying material.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        internal static byte[] Expand(HashAlgorithmName hashAlgorithmName, byte[] key, int outputLength, byte[] info = null)
        {
            if (key == null) { throw new ArgumentNullException(nameof(key), "Key cannot be null."); }
            if (info == null) { info = Array.Empty<byte>(); }
            int hashLength = GetHashLength(hashAlgorithmName);
            if (hashLength == 0) { throw new ArgumentOutOfRangeException(nameof(hashAlgorithmName), "Please specify a SHA2 algorithm."); }
            if (outputLength == 0 || outputLength > 255 * hashLength) { throw new ArgumentOutOfRangeException(nameof(outputLength), $"Output length must be greater than 0 and less than 255 * {hashLength}."); }
            int iterations = (int)Math.Ceiling((double)outputLength / hashLength);
            var counter = new byte[1];
            var previousHash = Array.Empty<byte>();
            var outputKeyingMaterial = new byte[outputLength];
            int bytesWritten = 0;
            using (var hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, key))
            {
                for (int i = 1; i <= iterations; i++)
                {
                    counter[0] = (byte)i;
                    hmac.AppendData(previousHash);
                    hmac.AppendData(info);
                    hmac.AppendData(counter);
                    previousHash = hmac.GetHashAndReset();
                    Array.Copy(previousHash, sourceIndex: 0, outputKeyingMaterial, bytesWritten, (i != iterations) ? previousHash.Length : outputLength - bytesWritten);
                    bytesWritten += hashLength;
                }
            }
            return outputKeyingMaterial;
        }

        private static int GetHashLength(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName == HashAlgorithmName.SHA256) { return 32; }
            if (hashAlgorithmName == HashAlgorithmName.SHA384) { return 48; }
            if (hashAlgorithmName == HashAlgorithmName.SHA512) { return 64; }
            return 0;
        }
    }
}
