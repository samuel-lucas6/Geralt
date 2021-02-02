using Geralt;
using Geralt.Exceptions;
using NUnit.Framework;
using System.Security.Cryptography;
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
    /// <summary>Exception tests for the StreamEncryption class</summary>
    [TestFixture]
    public class StreamEncryptionExceptionTest
    {
        [Test]
        public void StreamEncryptionEncryptBadKey()
        {
            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = XChaCha20.Encrypt(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("123456789012345678901234567890"));
              });

        }

        [Test]
        public void StreamEncryptionEncryptBadNonce()
        {
            _ = Assert.Throws<NonceOutOfRangeException>(() =>
              {
                  _ = XChaCha20.Encrypt(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
              });

        }

        [Test]
        public void StreamEncryptionDecryptBadKey()
        {
            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = XChaCha20.Decrypt(
              Utilities.HexToBinary("c7b7f04c00e14b02dd56c78c"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("123456789012345678901234567890"));
              });

        }

        [Test]
        public void StreamEncryptionDecryptBadNonce()
        {
            _ = Assert.Throws<NonceOutOfRangeException>(() =>
              {
                  _ = XChaCha20.Decrypt(
              Utilities.HexToBinary("c7b7f04c00e14b02dd56c78c"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
              });

        }

        [Test, Ignore("not implemented")]
        public void StreamEncryptionEncryptBadCrypto()
        {
            //TODO: implement
            _ = Assert.Throws<CryptographicException>(() =>
              {

              });
        }

        [Test, Ignore("not implemented")]
        public void StreamEncryptionDecryptBadCrypto()
        {
            //TODO: implement
            _ = Assert.Throws<CryptographicException>(() =>
              {

              });
        }

        [Test]
        public void StreamEncryptionEncryptChaCha20BadKey()
        {
            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = XChaCha20.EncryptChaCha20(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGH"),
              Encoding.UTF8.GetBytes("123456789012345678901234567890"));
              });

        }

        [Test]
        public void StreamEncryptionEncryptChaCha20BadNonce()
        {
            _ = Assert.Throws<NonceOutOfRangeException>(() =>
              {
                  _ = XChaCha20.EncryptChaCha20(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABC"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
              });

        }

        [Test]
        public void StreamEncryptionDecryptChaCha20BadKey()
        {
            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = XChaCha20.DecryptChaCha20(
              Utilities.HexToBinary("a6ce598d8b865fb328581bcd"),
              Encoding.UTF8.GetBytes("ABCDEFGH"),
              Encoding.UTF8.GetBytes("123456789012345678901234567890"));
              });

        }

        [Test]
        public void StreamEncryptionDecryptChaCha20BadNonce()
        {
            _ = Assert.Throws<NonceOutOfRangeException>(() =>
              {
                  _ = XChaCha20.DecryptChaCha20(
              Utilities.HexToBinary("a6ce598d8b865fb328581bcd"),
              Encoding.UTF8.GetBytes("ABC"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
              });
        }

        [Test, Ignore("not implemented")]
        public void StreamEncryptionEncryptChaCha20BadCrypto()
        {
            //TODO: implement
            _ = Assert.Throws<CryptographicException>(() =>
              {

              });
        }

        [Test, Ignore("not implemented")]
        public void StreamEncryptionDecryptChaCha20BadCrypto()
        {
            //TODO: implement
            _ = Assert.Throws<CryptographicException>(() =>
              {

              });
        }
    }
}
