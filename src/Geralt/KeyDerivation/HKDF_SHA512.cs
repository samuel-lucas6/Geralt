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
    /// <summary>Key derivation using HKDF-SHA512.</summary>
    public static class HKDF_SHA512
    {
        public const int SaltSize = 32;
        private const int _defaultOutputLength = 32;

        /// <summary>Derives a subkey from a master key.</summary>
        /// <remarks>A random 32 byte salt is recommended.</remarks>
        /// <param name="inputKeyingMaterial">The master key.</param>
        /// <param name="outputLength">The length of the output keying material.</param>
        /// <param name="salt">An optional, random salt.</param>
        /// <param name="info">Optional context information.</param>
        /// <returns>The output keying material.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static byte[] DeriveKey(byte[] inputKeyingMaterial, int outputLength = _defaultOutputLength, byte[] salt = null, byte[] info = null)
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA512, inputKeyingMaterial, outputLength, salt, info);
        }
    }
}
