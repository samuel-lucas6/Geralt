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
        /// <summary>Hashing streams using BLAKE2b.</summary>
        /// <remarks>See here for more information: https://doc.libsodium.org/hashing/generic_hashing </remarks>
        public class GenericHashAlgorithm : HashAlgorithm
        {
            private IntPtr HashStatePointer { get; set; }
            private byte[] Key { get; set; }
            private int Bytes { get; set; }

            /// <summary>Initializes the hashing algorithm.</summary>
            /// <param name="key">The key - may be null; otherwise, between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of the desired output.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="BytesOutOfRangeException"></exception>
            public GenericHashAlgorithm(string key, int bytes) : this(Encoding.UTF8.GetBytes(key), bytes) { }

            /// <summary>Initializes the hashing algorithm.</summary>
            /// <param name="key">The key - may be null; otherwise, between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of the desired output.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="BytesOutOfRangeException"></exception>
            public GenericHashAlgorithm(byte[] key, int bytes)
            {
                HashStatePointer = Marshal.AllocHGlobal(Marshal.SizeOf<LibsodiumLibrary.HashState>());
                Key = ParameterValidation.Key(key, _minKeyBytes, _maxKeyBytes);
                ParameterValidation.OutputLength(bytes, _minOutputBytes, _maxOutputBytes);
                Bytes = bytes;
                Initialize();
            }

            ~GenericHashAlgorithm()
            {
                Marshal.FreeHGlobal(HashStatePointer);
            }

            override public void Initialize()
            {
                _ = LibsodiumLibrary.crypto_generichash_init(HashStatePointer, Key, Key.Length, Bytes);
            }

            override protected void HashCore(byte[] array, int arrayOffset, int bytes)
            {
                byte[] message = new byte[bytes];
                Array.Copy(array, arrayOffset, message, destinationIndex: 0, bytes);
                _ = LibsodiumLibrary.crypto_generichash_update(HashStatePointer, message, bytes);
            }

            override protected byte[] HashFinal()
            {
                byte[] hash = new byte[Bytes];
                _ = LibsodiumLibrary.crypto_generichash_final(HashStatePointer, hash, Bytes);
                return hash;
            }
        }
    }
}
