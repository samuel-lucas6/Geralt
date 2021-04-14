using System;
using System.Text;

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
    /// <summary>Various utility methods.</summary>
    public static class Conversion
    {

        public static byte[] ToHex(byte[] data)
        {
            return Encoding.UTF8.GetBytes(BitConverter.ToString(data).Replace("-", "").ToLower());
        }

        public static byte[] FromHex(byte[] hex)
        {
            //if (hex.Length % 2 != 0)
            //{
            //    throw new FormatException("Hex strings cannot have an odd number of characters.");
            //}
            string hexString = Encoding.UTF8.GetString(hex);
            byte[] binary = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                binary[i / 2] = Convert.ToByte(hexString.Substring(startIndex: i, length: 2), fromBase: 16);
            }
            return binary;
        }

        public static byte[] ToBase64(byte[] data)
        {
            return Encoding.UTF8.GetBytes(Convert.ToBase64String(data));
        }

        public static byte[] FromBase64(byte[] base64)
        {
            return Convert.FromBase64String(Encoding.UTF8.GetString(base64));
        }
    }
}
