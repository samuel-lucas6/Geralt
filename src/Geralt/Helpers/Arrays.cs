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
    /// <summary>Concatenate byte arrays.</summary>
    public static class Arrays
    {
        private const int _index = 0;

        /// <summary>Concatenates two byte arrays.</summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns>The concatenated byte arrays.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] concat = new byte[a.Length + b.Length];
            Array.Copy(a, _index, concat, _index, a.Length);
            Array.Copy(b, _index, concat, a.Length, b.Length);
            return concat;
        }

        /// <summary>Concatenates three byte arrays.</summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <param name="c">The third byte array.</param>
        /// <returns>The concatenated byte arrays.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Concat(byte[] a, byte[] b, byte[] c)
        {
            byte[] concat = new byte[a.Length + b.Length + c.Length];
            Array.Copy(a, _index, concat, _index, a.Length);
            Array.Copy(b, _index, concat, a.Length, b.Length);
            Array.Copy(c, _index, concat, a.Length + b.Length, c.Length);
            return concat;
        }

        /// <summary>Concatenates four byte arrays.</summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <param name="c">The third byte array.</param>
        /// <param name="d">The fourth byte array.</param>
        /// <returns>The concatenated byte arrays.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Concat(byte[] a, byte[] b, byte[] c, byte[] d)
        {
            byte[] concat = new byte[a.Length + b.Length + c.Length + d.Length];
            Array.Copy(a, _index, concat, _index, a.Length);
            Array.Copy(b, _index, concat, a.Length, b.Length);
            Array.Copy(c, _index, concat, a.Length + b.Length, c.Length);
            Array.Copy(d, _index, concat, a.Length + b.Length + c.Length, d.Length);
            return concat;
        }

        /// <summary>Concatenates five byte arrays.</summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <param name="c">The third byte array.</param>
        /// <param name="d">The fourth byte array.</param>
        /// <param name="e">The fifth byte array.</param>
        /// <returns>The concatenated byte arrays.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Concat(byte[] a, byte[] b, byte[] c, byte[] d, byte[] e)
        {
            byte[] concat = new byte[a.Length + b.Length + c.Length + d.Length + e.Length];
            Array.Copy(a, _index, concat, _index, a.Length);
            Array.Copy(b, _index, concat, a.Length, b.Length);
            Array.Copy(c, _index, concat, a.Length + b.Length, c.Length);
            Array.Copy(d, _index, concat, a.Length + b.Length + c.Length, d.Length);
            Array.Copy(e, _index, concat, a.Length + b.Length + c.Length + d.Length, e.Length);
            return concat;
        }
    }
}
