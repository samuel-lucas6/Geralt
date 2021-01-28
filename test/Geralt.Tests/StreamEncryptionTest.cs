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
    /// <summary>Tests for the StreamEncryption class</summary>
    [TestFixture]
    public class StreamEncryptionTest
    {
        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateKey()
        {
            Assert.AreEqual(32, UnauthenticatedCiphers.GenerateKey().Length);
        }

        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateNonce()
        {
            Assert.AreEqual(24, UnauthenticatedCiphers.GenerateNonce().Length);
        }

        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateNonceChaCha20()
        {
            Assert.AreEqual(8, UnauthenticatedCiphers.GenerateNonceChaCha20().Length);
        }

        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateNonceXChaCha20()
        {
            Assert.AreEqual(24, UnauthenticatedCiphers.GenerateNonceXChaCha20().Length);
        }

        /// <summary>Does StreamEncryption.Encrypt() return the expected value?</summary>
        [Test]
        public void CreateSecretBox()
        {
            var expected = Utilities.HexToBinary("c7b7f04c00e14b02dd56c78c");
            var actual = UnauthenticatedCiphers.Encrypt(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
            Assert.AreEqual(expected, actual);
        }

        /// <summary>Does StreamEncryption.Decrypt() return the expected value?</summary>
        [Test]
        public void OpenSecretBox()
        {
            const string EXPECTED = "Adam Caudill";
            var actual = Encoding.UTF8.GetString(UnauthenticatedCiphers.Decrypt(
              Utilities.HexToBinary("c7b7f04c00e14b02dd56c78c"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012")));
            Assert.AreEqual(EXPECTED, actual);
        }

        /// <summary>Does StreamEncryption.EncryptChaCha20() return the expected value?</summary>
        [Test]
        public void CreateSecretBoxChaCha20()
        {
            var expected = Utilities.HexToBinary("a6ce598d8b865fb328581bcd");
            var actual = UnauthenticatedCiphers.EncryptChaCha20(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGH"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
            Assert.AreEqual(expected, actual);
        }

        /// <summary>Does StreamEncryption.DecryptChaCha20() return the expected value?</summary>
        [Test]
        public void OpenSecretBoxChaCha20()
        {
            const string EXPECTED = "Adam Caudill";
            var actual = Encoding.UTF8.GetString(UnauthenticatedCiphers.DecryptChaCha20(
              Utilities.HexToBinary("a6ce598d8b865fb328581bcd"),
              Encoding.UTF8.GetBytes("ABCDEFGH"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012")));
            Assert.AreEqual(EXPECTED, actual);
        }

        /// <summary>Does StreamEncryption.EncryptXChaCha20() return the expected value?</summary>
        [Test]
        public void CreateSecretBoxXChaCha20()
        {
            var expected = Utilities.HexToBinary("b99341769d6d1342541de1ad");
            var actual = UnauthenticatedCiphers.EncryptXChaCha20(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
            Assert.AreEqual(expected, actual);
        }

        /// <summary>Does StreamEncryption.DecryptXChaCha20() return the expected value?</summary>
        [Test]
        public void OpenSecretBoxXChaCha20()
        {
            const string EXPECTED = "Adam Caudill";
            var actual = Encoding.UTF8.GetString(UnauthenticatedCiphers.DecryptXChaCha20(
              Utilities.HexToBinary("b99341769d6d1342541de1ad"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012")));
            Assert.AreEqual(EXPECTED, actual);
        }
    }
}
