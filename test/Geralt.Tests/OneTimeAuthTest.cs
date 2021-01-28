using Geralt;
using NUnit.Framework;
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

namespace Tests
{
    /// <summary>Tests for the OneTimeAuth class</summary>
    [TestFixture]
    public class OneTimeAuthTest
    {
        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateKey()
        {
            Assert.AreEqual(32, Poly1305.GenerateKey().Length);
        }

        /// <summary>Does OneTimeAuth.Sign() return the expected value?</summary>
        [Test]
        public void SimpleAuthTest()
        {
            var expected = Utilities.HexToBinary("07577518b48b4980354844c8fe1b253f");
            var actual = Poly1305.Sign(Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does OneTimeAuth.Verify() return the expected value?</summary>
        [Test]
        public void SimpleVerifyTest()
        {
            var actual = Poly1305.Verify(Encoding.UTF8.GetBytes("Adam Caudill"),
              Utilities.HexToBinary("07577518b48b4980354844c8fe1b253f"),
              Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            Assert.AreEqual(true, actual);
        }
    }
}
