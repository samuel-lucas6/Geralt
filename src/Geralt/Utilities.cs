using System;
using System.Runtime.InteropServices;
using System.Text;

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
    /// <summary>Various utility methods.</summary>
    public static class Utilities
    {
        private static readonly string _encodingFailedError = "Internal error - encoding failed.";
        private static readonly string _decodingFailedError = "Internal error - decoding failed.";
        private static readonly string _nullDataError = "Data is null - encoding failed.";

        /// <summary>Represents hex formats.</summary>
        public enum HexFormat
        {
            /// <summary>A hex string without seperators.</summary>
            None,
            /// <summary>A hex string with colons (dd:33:dd).</summary>
            Colon,
            /// <summary>A hex string with hyphens (dd-33-dd).</summary>
            Hyphen,
            /// <summary>A hex string with spaces (dd 33 dd).</summary>
            Space
        }

        /// <summary>Represents hex cases.</summary>
        public enum HexCase
        {
            /// <summary>Lowercase hex encoded.</summary>
            Lower,
            /// <summary>Uppercase hex encoded</summary>
            Upper
        }

        /// <summary>Represents Base64 encoding variants.</summary>
        public enum Base64Variant
        {
            /// <summary>Original Base64 encoding variant.</summary>
            Original = 1,
            /// <summary>Original Base64 encoding variant with no padding.</summary>
            OriginalNoPadding = 3,
            /// <summary>Urlsafe Base64 encoding variant.</summary>
            UrlSafe = 5,
            /// <summary>Urlsafe Base64 encoding variant with no padding.</summary>
            UrlSafeNoPadding = 7
        }

        /// <summary>Takes a byte array and returns a hex encoded string.</summary>
        /// <param name="data">Data to be encoded.</param>
        /// <returns>A lowercase hex encoded string.</returns>
        /// <exception cref="OverflowException"></exception>
        public static string BinaryToHex(byte[] data)
        {
            byte[] hex = new byte[(data.Length * 2) + 1];
            IntPtr result = LibsodiumLibrary.sodium_bin2hex(hex, hex.Length, data, data.Length);
            return result == IntPtr.Zero ? throw new OverflowException(_encodingFailedError) : Marshal.PtrToStringAnsi(result);
        }

        /// <summary>Takes a byte array and returns a hex encoded string.</summary>
        /// <param name="data">Data to be encoded.</param>
        /// <param name="hexFormat">Output format.</param>
        /// <param name="hexCase">Lowercase or uppercase.</param>
        /// <returns>A hex encoded string.</returns>
        /// <remarks>Bit fiddling by CodeInChaos.</remarks>
        /// <remarks>This method doen't use libsodium, but it can be useful for generating human readable fingerprints.</remarks>
        public static string BinaryToHex(byte[] data, HexFormat hexFormat, HexCase hexCase = HexCase.Lower)
        {
            var stringBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                if ((i != 0) && (hexFormat != HexFormat.None))
                {
                    switch (hexFormat)
                    {
                        case HexFormat.Colon:
                            stringBuilder.Append((char)58);
                            break;
                        case HexFormat.Hyphen:
                            stringBuilder.Append((char)45);
                            break;
                        case HexFormat.Space:
                            stringBuilder.Append((char)32);
                            break;
                        default:
                            // No formatting
                            break;
                    }
                }
                int byteValue = data[i] >> 4;
                if (hexCase == HexCase.Lower)
                {
                    stringBuilder.Append((char)(87 + byteValue + (((byteValue - 10) >> 31) & -39)));
                }
                else
                {
                    stringBuilder.Append((char)(55 + byteValue + (((byteValue - 10) >> 31) & -7)));
                }
                byteValue = data[i] & 0xF;
                if (hexCase == HexCase.Lower)
                {
                    stringBuilder.Append((char)(87 + byteValue + (((byteValue - 10) >> 31) & -39)));
                }
                else
                {
                    stringBuilder.Append((char)(55 + byteValue + (((byteValue - 10) >> 31) & -7)));
                }
            }
            return stringBuilder.ToString();
        }

        /// <summary>Converts a hex encoded string to a byte array.</summary>
        /// <param name="hex">Hex encoded data.</param>
        /// <returns>A byte array of the decoded string.</returns>
        /// <exception cref="FormatException"></exception>
        public static byte[] HexToBinary(string hex)
        {
            const string ignoredCharacters = ":- ";
            byte[] decodedHex = new byte[hex.Length >> 1];
            IntPtr binaryPointer = Marshal.AllocHGlobal(decodedHex.Length);
            int result = LibsodiumLibrary.sodium_hex2bin(binaryPointer, decodedHex.Length, hex, hex.Length, ignoredCharacters, out int binaryLength, hexEnd: null);
            Marshal.Copy(binaryPointer, decodedHex, startIndex: 0, binaryLength);
            Marshal.FreeHGlobal(binaryPointer);
            if (result != 0)
            {
                throw new FormatException(_decodingFailedError);
            }
            // Remove the trailing nulls from the array if there were some format characters in the hex string before
            if (decodedHex.Length != binaryLength)
            {
                byte[] binaryWithoutPadding = new byte[binaryLength];
                Array.Copy(decodedHex, binaryWithoutPadding, binaryLength);
                return binaryWithoutPadding;
            }
            return decodedHex;
        }

        /// <summary>Takes a byte array and converts it into a Base64 encoded string.</summary>
        /// <param name="data">Data to be encoded.</param>
        /// <param name="variant">Base64 encoding variant.</param>
        /// <exception cref="OverflowException"></exception>
        /// <returns>A Base64 encoded string.</returns>
        public static string BinaryToBase64(byte[] data, Base64Variant variant = Base64Variant.Original)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), _nullDataError);
            }
            if (data.Length == 0)
            {
                return string.Empty;
            }
            int base64MaxLength = LibsodiumLibrary.sodium_base64_encoded_len(data.Length, (int)variant);
            byte[] base64 = new byte[base64MaxLength - 1];
            IntPtr base64Pointer = LibsodiumLibrary.sodium_bin2base64(base64, base64MaxLength, data, data.Length, (int)variant);
            return base64Pointer == IntPtr.Zero ? throw new OverflowException(_encodingFailedError) : Marshal.PtrToStringAnsi(base64Pointer);
        }

        /// <summary>Converts a Base64 encoded string to a byte array.</summary>
        /// <param name="base64">Base64 encoded string.</param>
        /// <param name="ignoredChars">Characters which will be ignored in decoding.</param>
        /// <param name="variant">Base64 encoding variant.</param>
        /// <exception cref="FormatException"></exception>
        /// <returns>A byte array of the decoded Base64 string</returns>
        public static byte[] Base64ToBinary(string base64, string ignoredChars, Base64Variant variant = Base64Variant.Original)
        {
            if (base64 == null)
            {
                throw new ArgumentNullException(nameof(base64), _nullDataError);
            }
            if (base64 == string.Empty)
            {
                return Array.Empty<byte>();
            }
            IntPtr decodedBase64Pointer = Marshal.AllocHGlobal(base64.Length);
            int result = LibsodiumLibrary.sodium_base642bin(decodedBase64Pointer, base64.Length, base64, base64.Length, ignoredChars, out int decodedLength, out _, (int)variant);
            if (result != 0)
            {
                throw new FormatException(_decodingFailedError);
            }
            byte[] decodedBase64 = new byte[decodedLength];
            Marshal.Copy(decodedBase64Pointer, decodedBase64, startIndex: 0, decodedLength);
            Marshal.FreeHGlobal(decodedBase64Pointer);
            return decodedBase64;
        }

        /// <summary>Takes a byte array and increments it.</summary>
        /// <param name="value">The value to increment.</param>
        /// <returns>The incremented byte array.</returns>
        public static byte[] Increment(byte[] value)
        {
            byte[] buffer = value;
            LibsodiumLibrary.sodium_increment(buffer, buffer.Length);
            return buffer;
        }

        /// <summary>Compares two byte arrays in constant time.</summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns><c>true</c> if the values are equal, otherwise <c>false</c>.</returns>
        public static bool Compare(byte[] a, byte[] b)
        {
            int result = LibsodiumLibrary.sodium_compare(a, b, a.Length);
            return result == 0;
        }

        internal static string UnsafeAsciiBytesToString(byte[] buffer)
        {
            unsafe
            {
                fixed (byte* ascii = buffer)
                {
                    return new string((sbyte*)ascii, startIndex: 0, buffer.Length);
                }
            }
        }
    }
}
