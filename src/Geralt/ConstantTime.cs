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
    /// <summary>Constant time methods.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/helpers </remarks>
    public static class ConstantTime
    {
        /// <summary>Increments a byte array in constant time.</summary>
        /// <remarks>This should be used to increment a counter nonce.</remarks>
        /// <param name="array">The byte array to increment.</param>
        /// <returns>The incremented byte array.</returns>
        public static byte[] Increment(byte[] array)
        {
            LibsodiumLibrary.sodium_increment(array, array.Length);
            return array;
        }

        /// <summary>Compares two byte arrays of the same length in constant time.</summary>
        /// <remarks>This should be used to compare authentication tags.</remarks>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns><c>true</c> if the values are equal; otherwise, <c>false</c>.</returns>
        public static bool Compare(byte[] a, byte[] b)
        {
            int result = LibsodiumLibrary.sodium_compare(a, b, a.Length);
            return result == 0;
        }
    }
}
