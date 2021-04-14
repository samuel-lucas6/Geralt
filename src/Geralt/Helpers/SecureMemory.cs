using System;
using System.Runtime.CompilerServices;

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
    /// <summary>Clear arrays containing sensitive data.</summary>
    /// <remarks>Note that arrays must be pinned to prevent copies in memory.</remarks>
    public static class SecureMemory
    {
        private const int _index = 0;

        /// <summary>Clears a byte array containing sensitive data.</summary>
        /// <remarks>If the array isn't pinned, there might still be copies in memory after this call.</remarks>
        /// <param name="array">The byte array to clear.</param>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void ZeroArray(byte[] array)
        {
            if (array != null)
            {
                Array.Clear(array, _index, array.Length);
            }
        }

        /// <summary>Clears a char array containing sensitive data.</summary>
        /// <remarks>If the array isn't pinned, there might still be copies in memory after this call.</remarks>
        /// <param name="array">The char array to clear.</param>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void ZeroArray(char[] array)
        {
            if (array.Length > 0)
            {
                Array.Clear(array, _index, array.Length);
            }
        }
    }
}
