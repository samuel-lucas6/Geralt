using Geralt.Exceptions;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

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
    public partial class BLAKE2b
    {
        /// <summary>Hashing streams using BLAKE2b.</summary>
        public class Stream : HashAlgorithm
        {
            private IntPtr HashStatePointer { get; set; }
            private byte[] Key { get; set; }
            private int OutputLength { get; set; }

            /// <summary>Initializes the hash algorithm.</summary>
            /// <remarks>The output length should be 32 or 64 bytes.</remarks>
            /// <param name="length">The length of the hash in bytes.</param>
            /// <exception cref="LengthOutOfRangeException"></exception>
            public Stream(int length = HashLength)
            {
                HashStatePointer = Marshal.AllocHGlobal(Marshal.SizeOf<LibsodiumLibrary.HashState>());
                Key = Array.Empty<byte>();
                ParameterValidation.OutputLength(length, _minLength, _maxLength);
                OutputLength = length;
                Initialize();
            }

            /// <summary>Initializes the hash algorithm.</summary>
            /// <remarks>The authentication tag length should be 32 or 64 bytes.</remarks>
            /// <param name="key">The 32 or 64 byte key.</param>
            /// <param name="length">The length of the authentication tag in bytes.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="LengthOutOfRangeException"></exception>
            public Stream(byte[] key, int length = MACLength)
            {
                HashStatePointer = Marshal.AllocHGlobal(Marshal.SizeOf<LibsodiumLibrary.HashState>());
                Key = ParameterValidation.Key(key, _minKeySize, _maxKeySize);
                ParameterValidation.OutputLength(length, _minLength, _maxLength);
                OutputLength = length;
                Initialize();
            }

            ~Stream()
            {
                Marshal.FreeHGlobal(HashStatePointer);
            }

            override public void Initialize()
            {
                _ = LibsodiumLibrary.crypto_generichash_init(HashStatePointer, Key, Key.Length, OutputLength);
            }

            override protected void HashCore(byte[] array, int offset, int length)
            {
                byte[] message = new byte[length];
                Array.Copy(array, offset, message, destinationIndex: 0, length);
                _ = LibsodiumLibrary.crypto_generichash_update(HashStatePointer, message, length);
            }

            override protected byte[] HashFinal()
            {
                byte[] hash = new byte[OutputLength];
                _ = LibsodiumLibrary.crypto_generichash_final(HashStatePointer, hash, OutputLength);
                return hash;
            }
        }
    }
}
