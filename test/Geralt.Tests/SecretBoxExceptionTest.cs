using Geralt;
using Geralt.Exceptions;
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
    /// <summary>Exception tests for the SecretBox class</summary>
    [TestFixture]
    public class SecretBoxExceptionTest
    {
        [Test]
        public void CreateSecretBoxBadKey()
        {
            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = XSalsa20Poly1305.Create(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("123456789012345678901234567890"));
              });
        }

        [Test]
        public void CreateSecretBoxBadNonce()
        {
            _ = Assert.Throws<NonceOutOfRangeException>(() =>
              {
                  _ = XSalsa20Poly1305.Create(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
              });
        }

        [Test]
        public void CreateDetachedSecretBoxBadKey()
        {
            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = XSalsa20Poly1305.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("123456789012345678901234567890"));
              });
        }

        [Test]
        public void CreateDetachedSecretBoxBadNonce()
        {
            _ = Assert.Throws<NonceOutOfRangeException>(() =>
              {
                  _ = XSalsa20Poly1305.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
              });
        }

        [Test]
        public void OpenSecretBoxBadKey()
        {
            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = XSalsa20Poly1305.Open(
              Utilities.HexToBinary("00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("123456789012345678901234567890"));
              });
        }

        [Test]
        public void OpenSecretBoxBadNonce()
        {
            _ = Assert.Throws<NonceOutOfRangeException>(() =>
              {
                  _ = XSalsa20Poly1305.Open(
              Utilities.HexToBinary("00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
              });
        }

        [Test]
        public void OpenDetachedSecretBoxBadKey()
        {
            var actual = XSalsa20Poly1305.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                XSalsa20Poly1305.OpenDetached(actual.Ciphertext, actual.Mac,
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
            Encoding.UTF8.GetBytes("123456789012345678901234567890"));
            });
        }

        [Test]
        public void OpenDetachedSecretBoxBadNonce()
        {
            var actual = XSalsa20Poly1305.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            Assert.Throws<NonceOutOfRangeException>(() =>
            {
                XSalsa20Poly1305.OpenDetached(actual.Ciphertext, actual.Mac,
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
            Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
            });
        }

        [Test]
        public void OpenDetachedSecretBoxBadMac()
        {
            var actual = XSalsa20Poly1305.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            _ = Assert.Throws<TagOutOfRangeException>(() =>
              {
                  _ = XSalsa20Poly1305.OpenDetached(actual.Ciphertext, null,
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
              });
        }
    }
}
