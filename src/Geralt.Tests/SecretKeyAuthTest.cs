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
    /// <summary>Tests for the SecretKeyAuth class</summary>
    [TestFixture]
    public class SecretKeyAuthTest
    {
        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateKey()
        {
            Assert.AreEqual(32, HMAC.GenerateKey().Length);
        }

        /// <summary>Does SecretKeyAuth.Sign() return the expected value?</summary>
        [Test]
        public void SimpleAuthTest()
        {
            var expected = Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c0");
            var actual = HMAC.Sign(Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does SecretKeyAuth.SignHmacSha256() return the expected value?</summary>
        [Test]
        public void SimpleAuthHmacSha256Test()
        {
            var expected = Utilities.HexToBinary("1cc0012cfd200becfce64bba779025d02cb349d203e15d44a308e4249e2b7245");
            var actual = HMAC.SignHmacSha256(Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does SecretKeyAuth.SignHmacSha512() return the expected value?</summary>
        [Test]
        public void SimpleAuthHmacSha512Test()
        {
            var expected = Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c06a99b828e2ff921b4d1304bbd9480adfacf8c4c2ffbcbb4e5663446fda1235d2");
            var actual = HMAC.SignHmacSha512(Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does SecretKeyAuth.Verify() return the expected value?</summary>
        [Test]
        public void SimpleVerifyTest()
        {
            var actual = HMAC.Verify(Encoding.UTF8.GetBytes("Adam Caudill"),
              Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c0"),
              Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            Assert.AreEqual(true, actual);
        }

        /// <summary>Does SecretKeyAuth.VerifyHmacSha256() return the expected value?</summary>
        [Test]
        public void SimpleVerifyHmacSha256Test()
        {
            var actual = HMAC.VerifyHmacSha256(Encoding.UTF8.GetBytes("Adam Caudill"),
              Utilities.HexToBinary("1cc0012cfd200becfce64bba779025d02cb349d203e15d44a308e4249e2b7245"),
              Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            Assert.AreEqual(true, actual);
        }

        /// <summary>Does SecretKeyAuth.VerifyHmacSha512() return the expected value?</summary>
        [Test]
        public void SimpleVerifyHmacSha512Test()
        {
            var actual = HMAC.VerifyHmacSha512(Encoding.UTF8.GetBytes("Adam Caudill"),
              Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c06a99b828e2ff921b4d1304bbd9480adfacf8c4c2ffbcbb4e5663446fda1235d2"),
              Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            Assert.AreEqual(true, actual);
        }
    }
}
