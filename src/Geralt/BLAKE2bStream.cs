using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
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
    public partial class BLAKE2b
    {
        /// <summary>BLAKE2b for hashing streams.</summary>
        public class GenericHashAlgorithm : HashAlgorithm
        {
            private IntPtr hashStatePtr;
            private byte[] key;
            private int bytes;

            /// <summary>
            /// Initializes the hashing algorithm.
            /// </summary>
            /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of the desired result.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="BytesOutOfRangeException"></exception>
            public GenericHashAlgorithm(string key, int bytes) : this(Encoding.UTF8.GetBytes(key), bytes) { }

            /// <summary>
            /// Initializes the hashing algorithm.
            /// </summary>
            /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of the desired result.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="BytesOutOfRangeException"></exception>
            public GenericHashAlgorithm(byte[] key, int bytes)
            {
                this.hashStatePtr = Marshal.AllocHGlobal(Marshal.SizeOf<LibsodiumLibrary.HashState>());

                //validate the length of the key
                int keyLength;
                if (key != null)
                {
                    if (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN)
                    {
                        throw new KeyOutOfRangeException(string.Format("key must be between {0} and {1} bytes in length.",
                          KEY_BYTES_MIN, KEY_BYTES_MAX));
                    }

                    keyLength = key.Length;
                }
                else
                {
                    key = new byte[0];
                    keyLength = 0;
                }

                this.key = key;

                //validate output length
                if (bytes > BYTES_MAX || bytes < BYTES_MIN)
                    throw new BytesOutOfRangeException("bytes", bytes,
                      string.Format("bytes must be between {0} and {1} bytes in length.", BYTES_MIN, BYTES_MAX));

                this.bytes = bytes;

                Initialize();
            }

            ~GenericHashAlgorithm()
            {
                Marshal.FreeHGlobal(hashStatePtr);
            }

            override public void Initialize()
            {
                LibsodiumLibrary.crypto_generichash_init(hashStatePtr, key, key.Length, bytes);
            }

            override protected void HashCore(byte[] array, int ibStart, int cbSize)
            {
                byte[] subArray = new byte[cbSize];
                Array.Copy(array, ibStart, subArray, 0, cbSize);
                LibsodiumLibrary.crypto_generichash_update(hashStatePtr, subArray, cbSize);
            }

            override protected byte[] HashFinal()
            {
                byte[] buffer = new byte[bytes];
                LibsodiumLibrary.crypto_generichash_final(hashStatePtr, buffer, bytes);
                return buffer;
            }
        }
    }
}
