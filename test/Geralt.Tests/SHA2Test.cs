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
    /// <summary>Tests for the SHA2 class.</summary>
    [TestFixture]
    public class SHA2Test
    {
        private const string _message = "There’s some good in this world, Mr. Frodo and it’s worth fighting for.";
        private const string _sha512 = "d6212d4ddf0f6179ac21290c421880528ddacb6dafd8d2cbe98c5cf1f586d19738ca45b7ade0778474441ec17933e6173e37ae9458dd5eb86eb733631753f4cf";
        private const string _sha256 = "e5e343a0dafc3db0a14a53454e3046548cbdd65a7642143d87c4ca62ca75d11e";

        /// <summary>Does SHA2.Hash(string) return the expected value?</summary>
        [Test]
        public void HashStringTest()
        {
            byte[] hash = SHA2.Hash(_message);
            CollectionAssert.AreEqual(Utilities.HexToBinary(_sha512), hash);
        }

        /// <summary>Does SHA2.Hash(byte[]) return the expected value?</summary>
        [Test]
        public void HashBytesTest()
        {
            byte[] hash = SHA2.Hash(Encoding.UTF8.GetBytes(_message));
            CollectionAssert.AreEqual(Utilities.HexToBinary(_sha512), hash);
        }

        /// <summary>Does SHA2.Sha512(string) return the expected value?</summary>
        [Test]
        public void HashSha512StringTest()
        {
            byte[] hash = SHA2.Sha512(_message);
            CollectionAssert.AreEqual(Utilities.HexToBinary(_sha512), hash);
        }

        /// <summary>Does SHA2.Sha512(byte[]) return the expected value?</summary>
        [Test]
        public void HashSha512BytesTest()
        {
            byte[] hash = SHA2.Sha512(Encoding.UTF8.GetBytes(_message));
            CollectionAssert.AreEqual(Utilities.HexToBinary(_sha512), hash);
        }

        /// <summary>Does SHA2.Sha256(string) return the expected value?</summary>
        [Test]
        public void HashSha256StringTest()
        {
            byte[] hash = SHA2.Sha256(_message);
            CollectionAssert.AreEqual(Utilities.HexToBinary(_sha256), hash);
        }

        /// <summary>Does SHA2.Sha256(byte[]) return the expected value?</summary>
        [Test]
        public void HashSha256BytesTest()
        {
            byte[] hash = SHA2.Sha256(Encoding.UTF8.GetBytes(_message));
            CollectionAssert.AreEqual(Utilities.HexToBinary(_sha256), hash);
        }
    }
}
