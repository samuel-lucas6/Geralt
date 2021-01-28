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
    /// <summary>Tests for the CryptoHash class</summary>
    [TestFixture]
    public class CryptoHashTest
    {
        //hashes of "Adam Caudill"
        private const string SHA512_HASH = "be4102c89b6d8af4be54ef72d66a19f49d86e245adb83019118fff716eabd3f27cfc2fa98285d239eb56e70249cffe814e385180caf6b3f7a31a133a34b2aa7e";

        private const string SHA256_HASH = "00b7d1c5871ebc343c24114f87434a9af321405606fbde47d33278ed21f2e068";

        /// <summary>Does CryptoHash.Hash(string) return the expected value?</summary>
        [Test]
        public void CryptoHashStringTest()
        {
            var actual = SHA2.Hash("Adam Caudill");
            CollectionAssert.AreEqual(Utilities.HexToBinary(SHA512_HASH), actual);
        }

        /// <summary>Does CryptoHash.Hash(byte[]) return the expected value?</summary>
        [Test]
        public void CryptoHashArrayTest()
        {
            var actual = SHA2.Hash(Encoding.UTF8.GetBytes("Adam Caudill"));
            CollectionAssert.AreEqual(Utilities.HexToBinary(SHA512_HASH), actual);
        }

        /// <summary>Does CryptoHash.Sha512(string) return the expected value?</summary>
        [Test]
        public void CryptoHashSha512StringTest()
        {
            var actual = SHA2.Sha512("Adam Caudill");
            CollectionAssert.AreEqual(Utilities.HexToBinary(SHA512_HASH), actual);
        }

        /// <summary>Does CryptoHash.Sha512(byte[]) return the expected value?</summary>
        [Test]
        public void CryptoHashSha512ArrayTest()
        {
            var actual = SHA2.Sha512(Encoding.UTF8.GetBytes("Adam Caudill"));
            CollectionAssert.AreEqual(Utilities.HexToBinary(SHA512_HASH), actual);
        }

        /// <summary>Does CryptoHash.Sha256(string) return the expected value?</summary>
        [Test]
        public void CryptoHashSha256StringTest()
        {
            var actual = SHA2.Sha256("Adam Caudill");
            CollectionAssert.AreEqual(Utilities.HexToBinary(SHA256_HASH), actual);
        }

        /// <summary>Does CryptoHash.Sha256(byte[]) return the expected value?</summary>
        [Test]
        public void CryptoHashSha256ArrayTest()
        {
            var actual = SHA2.Sha256(Encoding.UTF8.GetBytes("Adam Caudill"));
            CollectionAssert.AreEqual(Utilities.HexToBinary(SHA256_HASH), actual);
        }
    }
}
