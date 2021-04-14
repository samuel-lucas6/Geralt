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
    /// <summary>ISO/IEC 7816-4 padding for byte arrays.</summary>
    public static class Padding
    {
        private const byte _mandatoryByte = 0x80;

        /// <summary>Applies ISO/IEC 7816-4 padding to a byte array.</summary>
        /// <remarks>This can be used to hide the length of a message before authenticated encryption.</remarks>
        /// <param name="array">The byte array to pad.</param>
        /// <param name="paddingLength">The length of the padding in bytes.</param>
        /// <returns>The array with padding.</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] ApplyPadding(byte[] array, int paddingLength)
        {
            if (paddingLength <= 0) { throw new ArgumentException("Padding length must be greater than 0."); }
            byte[] padding = new byte[paddingLength];
            padding[0] = _mandatoryByte;
            return Arrays.Concat(array, padding);
        }

        /// <summary>Removes ISO/IEC 7816-4 padding from a byte array.</summary>
        /// <remarks>This can be used to unpad a message after decryption.</remarks>
        /// <param name="paddedArray">The padded byte array.</param>
        /// <returns>The array without padding.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static byte[] RemovePadding(byte[] paddedArray)
        {
            int i = paddedArray.Length - 1;
            if (paddedArray[i] != 0 && paddedArray[i] != _mandatoryByte)
            {
                return paddedArray;
            }
            while (paddedArray[i] == 0)
            {
                i--;
            }
            if (paddedArray[i] != _mandatoryByte)
            {
                throw new ArgumentException("Invalid padding.");
            }
            byte[] unpaddedArray = new byte[paddedArray.Length - (paddedArray.Length - i)];
            Array.Copy(paddedArray, unpaddedArray, unpaddedArray.Length);
            return unpaddedArray;
        }
    }
}
