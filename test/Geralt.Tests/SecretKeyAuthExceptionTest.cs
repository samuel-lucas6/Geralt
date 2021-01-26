using System.Text;
using NUnit.Framework;
using Geralt.Exceptions;
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
    /// <summary>Exception tests for the SecretKeyAuth class</summary>
    [TestFixture]
    public class SecretKeyAuthExceptionTest
    {
        [Test]
        public void SecretKeyAuthSignWithBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                SecretKeyAuth.Sign(Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("0123456789012345678901234567890"));
            });
        }

        [Test]
        public void SecretKeyAuthSign256WithBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                SecretKeyAuth.SignHmacSha256(Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("012345678901234567890123456789"));
            });
        }

        [Test]
        public void SecretKeyAuthSign512WithBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                SecretKeyAuth.SignHmacSha512(Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("012345678901234567890123456789"));
            });

        }

        [Test]
        public void SecretKeyAuthVerifyWithBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                SecretKeyAuth.Verify(Encoding.UTF8.GetBytes("Adam Caudill"),
            Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c0"),
            Encoding.UTF8.GetBytes("012345678901234567890123456789"));
            });

        }

        [Test]
        public void SecretKeyAuthVerifyWithBadSignature()
        {
            Assert.Throws<SignatureOutOfRangeException>(() =>
            {
                SecretKeyAuth.Verify(Encoding.UTF8.GetBytes("Adam Caudill"),
            Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321"),
            Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            });

        }

        [Test]
        public void SecretKeyAuthVerify256WithBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                SecretKeyAuth.VerifyHmacSha256(Encoding.UTF8.GetBytes("Adam Caudill"),
            Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c0"),
            Encoding.UTF8.GetBytes("012345678901234567890123456789"));
            });

        }

        [Test]
        public void SecretKeyAuthVerify256WithBadSignature()
        {
            Assert.Throws<SignatureOutOfRangeException>(() =>
            {
                SecretKeyAuth.VerifyHmacSha256(Encoding.UTF8.GetBytes("Adam Caudill"),
            Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321"),
            Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            });

        }

        [Test]
        public void SecretKeyAuthVerify512WithBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                SecretKeyAuth.VerifyHmacSha512(Encoding.UTF8.GetBytes("Adam Caudill"),
            Utilities.HexToBinary(
              "9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c06a99b828e2ff921b4d1304bbd9480adfacf8c4c2ffbcbb4e5663446fda1235d2"),
            Encoding.UTF8.GetBytes("012345678901234567890123456789"));
            });

        }

        [Test]
        public void SecretKeyAuthVerify512WithBadSignature()
        {
            Assert.Throws<SignatureOutOfRangeException>(() =>
            {
                SecretKeyAuth.VerifyHmacSha512(Encoding.UTF8.GetBytes("Adam Caudill"),
            Utilities.HexToBinary(
              "9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c06a99b828e2ff921b4d1304bbd9480adfacf8c4c2ffbcbb4e5663446fda1235"),
            Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            });
        }
    }
}
