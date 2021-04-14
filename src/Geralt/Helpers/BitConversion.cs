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
    /// <summary>Convert different data types to little-endian bytes.</summary>
    public static class BitConversion
    {
        /// <summary>Converts a short into a little-endian byte array.</summary>
        /// <param name="value">The short to convert.</param>
        /// <returns>A byte array containing 2 bytes.</returns>
        public static byte[] GetBytes(short value)
        {
            byte[] valueBytes = BitConverter.GetBytes(value);
            return ToLittleEndian(valueBytes);
        }

        /// <summary>Converts an integer into a little-endian byte array.</summary>
        /// <param name="value">The integer to convert.</param>
        /// <returns>A byte array containing 4 bytes.</returns>
        public static byte[] GetBytes(int value)
        {
            byte[] valueBytes = BitConverter.GetBytes(value);
            return ToLittleEndian(valueBytes);
        }

        /// <summary>Converts a long into a little-endian byte array.</summary>
        /// <param name="value">The long to convert.</param>
        /// <returns>A byte array containing 8 bytes.</returns>
        public static byte[] GetBytes(long value)
        {
            byte[] valueBytes = BitConverter.GetBytes(value);
            return ToLittleEndian(valueBytes);
        }

        /// <summary>Converts a double into a little-endian byte array.</summary>
        /// <param name="value">The long to convert.</param>
        /// <returns>A byte array containing 8 bytes.</returns>
        public static byte[] GetBytes(double value)
        {
            byte[] valueBytes = BitConverter.GetBytes(value);
            return ToLittleEndian(valueBytes);
        }

        /// <summary>Converts a byte array containing 2 bytes into a short.</summary>
        /// <param name="value">The byte array to convert.</param>
        /// <returns>The short.</returns>
        public static short ToShort(byte[] value)
        {
            value = ToLittleEndian(value);
            return BitConverter.ToInt16(value, startIndex: 0);
        }

        /// <summary>Converts a byte array containing 4 bytes into an integer.</summary>
        /// <param name="value">The byte array to convert.</param>
        /// <returns>The integer.</returns>
        public static int ToInt32(byte[] value)
        {
            value = ToLittleEndian(value);
            return BitConverter.ToInt32(value, startIndex: 0);
        }

        /// <summary>Converts a byte array containing 8 bytes into a long.</summary>
        /// <param name="value">The byte array to convert.</param>
        /// <returns>The long.</returns>
        public static long ToLong(byte[] value)
        {
            value = ToLittleEndian(value);
            return BitConverter.ToInt64(value, startIndex: 0);
        }

        /// <summary>Converts a byte array containing 8 bytes into a double.</summary>
        /// <param name="value">The byte array to convert.</param>
        /// <returns>The double.</returns>
        public static double ToDouble(byte[] value)
        {
            value = ToLittleEndian(value);
            return BitConverter.ToDouble(value, startIndex: 0);
        }

        /// <summary>Converts a byte array into little-endian.</summary>
        /// <param name="value">The byte array to convert.</param>
        /// <returns>The little-endian byte array.</returns>
        private static byte[] ToLittleEndian(byte[] value)
        {
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(value);
            }
            return value;
        }
    }
}
