using System;

/*
    Geralt: A cryptographic library for .NET based on libsodium.
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
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
    COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

namespace Geralt
{
    internal static class Nonce
    {
        internal static byte[] Read(byte[] ciphertext, int nonceLength)
        {
            byte[] nonce = new byte[nonceLength];
            Array.Copy(ciphertext, nonce, nonceLength);
            return nonce;
        }

        internal static byte[] Remove(byte[] ciphertextWithNonce, int nonceLength)
        {
            byte[] ciphertext = new byte[ciphertextWithNonce.Length - nonceLength];
            Array.Copy(ciphertextWithNonce, nonceLength, ciphertext, destinationIndex: 0, ciphertext.Length);
            return ciphertext;
        }
    }
}
