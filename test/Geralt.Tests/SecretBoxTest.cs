using System.Text;
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
    /// <summary>Tests for the SecretBox class</summary>
    [TestFixture]
    public class SecretBoxTest
    {
        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateKey()
        {
            Assert.AreEqual(32, SecretBox.GenerateKey().Length);
        }

        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateNonce()
        {
            Assert.AreEqual(24, SecretBox.GenerateNonce().Length);
        }

        /// <summary>Does SecretBox.Create() return the expected value?</summary>
        [Test]
        public void CreateSecretBox()
        {
            var expected = Utilities.HexToBinary("b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164");
            var actual = SecretBox.Create(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does SecretBox.open() return the expected value?</summary>
        [Test]
        public void OpenSecretBox()
        {
            const string EXPECTED = "Adam Caudill";
            var actual = Encoding.UTF8.GetString(SecretBox.Open(
              Utilities.HexToBinary("b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012")));

            Assert.AreEqual(EXPECTED, actual);
        }

        /// <summary>Does SecretBox.open() return the expected value?</summary>
        [Test]
        public void OpenSecretBoxWithPadding()
        {
            const string EXPECTED = "Adam Caudill";
            var actual = Encoding.UTF8.GetString(SecretBox.Open(
              Utilities.HexToBinary("00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012")));

            Assert.AreEqual(EXPECTED, actual);
        }

        /// <summary>Does SecretBox.CreateDetached() and SecretBox.OpenDetached() work?</summary>
        [Test]
        public void DetachedSecretBox()
        {
            var expected = Utilities.HexToBinary("4164616d2043617564696c6c");
            var actual = SecretBox.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            var clear = SecretBox.OpenDetached(actual.CipherText, actual.Mac,
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            Assert.AreEqual(clear, expected);
        }
    }
}
