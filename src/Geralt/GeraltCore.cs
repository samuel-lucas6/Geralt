using System.Runtime.InteropServices;

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
    /// <summary>
    /// libsodium core information.
    /// </summary>
    public static class GeraltCore
    {
        private static bool _isInit;

        static GeraltCore()
        {
            Init();
        }

        /// <summary>Gets random bytes</summary>
        /// <param name="count">The count of bytes to return.</param>
        /// <returns>An array of random bytes.</returns>
        public static byte[] GetRandomBytes(int count)
        {
            var buffer = new byte[count];
            LibsodiumLibrary.randombytes_buf(buffer, count);

            return buffer;
        }

        /// <summary>
        /// Gets a random number.
        /// </summary>
        /// <param name="upperBound">Integer between 0 and 2147483647.</param>
        /// <returns>An unpredictable value between 0 and upperBound (excluded).</returns>
        public static int GetRandomNumber(int upperBound)
        {
            var randomNumber = LibsodiumLibrary.randombytes_uniform(upperBound);

            return randomNumber;
        }

        /// <summary>
        /// Returns the version of libsodium in use.
        /// </summary>
        /// <returns>
        /// The sodium version string.
        /// </returns>
        public static string SodiumVersionString()
        {
            var ptr = LibsodiumLibrary.sodium_version_string();

            return Marshal.PtrToStringAnsi(ptr);
        }

        /// <summary>Initialize libsodium.</summary>
        /// <remarks>This only needs to be done once, so this prevents repeated calls.</remarks>
        public static void Init()
        {
            if (!_isInit)
            {
                LibsodiumLibrary.sodium_init();
                _isInit = true;
            }
        }
    }
}
