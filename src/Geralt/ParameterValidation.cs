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
    }
}
