using NUnit.Framework;
using Geralt;

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
    /// <summary>Tests for Random Bytes support</summary>
    [TestFixture]
    public class RandomBytesTest
    {
        /// <summary>Does SodiumCore.GetRandomBytes() return something</summary>
        [Test]
        public void GetRandomBytesTest()
        {
            var v16 = GeraltCore.GetRandomBytes(16);
            var v32 = GeraltCore.GetRandomBytes(32);
            var v64 = GeraltCore.GetRandomBytes(64);

            Assert.IsNotNull(v16);
            Assert.IsNotNull(v32);
            Assert.IsNotNull(v64);

            Assert.AreEqual(16U, v16.Length);
            Assert.AreEqual(32U, v32.Length);
            Assert.AreEqual(64U, v64.Length);
        }
    }
}
