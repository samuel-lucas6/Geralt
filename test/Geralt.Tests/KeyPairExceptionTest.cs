using Geralt;
using Geralt.Exceptions;
using NUnit.Framework;

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

namespace Tests
{
    /// <summary>Exception tests for the KeyPair class</summary>
    [TestFixture]
    public class KeyPairExceptionTest
    {
        [Test]
        public void KeyPairModuloTest()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
                0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
                0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
                0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
                0x1c,0x2f,0x8b,0x27,0xff,0x88
            };

            //32 byte
            var bobPk = new byte[] {
                0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
                0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
                0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
                0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
            };

            _ = Assert.Throws<KeyOutOfRangeException>(() => new KeyPair(bobPk, bobSk));
        }
    }
}
