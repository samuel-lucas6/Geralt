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
    /// <summary>Tests for the GenericHash class</summary>
    [TestFixture]
    public class GenericHashTest
    {
        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateKey()
        {
            Assert.AreEqual(64, BLAKE2b.GenerateKey().Length);
        }

        /// <summary>BLAKE2b, 32 bytes, no key</summary>
        [Test]
        public void GenericHashNoKey()
        {
            var expected = Utilities.HexToBinary("53e27925e5786abe74e6bb7004980a6a38a8da2478efa1b6b2ae73964cfe4876");
            var actual = BLAKE2b.Hash(Encoding.UTF8.GetBytes("Adam Caudill"), null, 32);
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>BLAKE2b, 32 bytes, with key</summary>
        [Test]
        public void GenericHashWithKey()
        {
            var expected = Utilities.HexToBinary("8866267f985204ae511980704ac85ec4936ee535c37541f342976b2cb3ac62fd");
            var actual = BLAKE2b.Hash("Adam Caudill", "This is a test key", 32);
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Generics the hash salt personal.</summary>
        [Test]
        public void GenericHashSaltPersonal()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";

            const string EXPECTED = "2a4ed94ed58eb8d099f52a5ebed051648cc34f29dccd0f25b215e28672b28de8f86a4666d60456ea93e25c5f1fbec1387d861e2b9ab498169a2ad2da3649f84b";
            var actual = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, PERSONAL));

            Assert.AreEqual(EXPECTED, actual);
        }

        /// <summary>Generics the hash salt personal, 32 bytes.</summary>
        [Test]
        public void GenericHashSaltPersonalBytes()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";

            const string EXPECTED = "5bdaa4980b3d07a3fdde996b967d46f85df0f8eeb27cc823ef835a976af77b27";
            var actual = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, PERSONAL, 32));

            Assert.AreEqual(EXPECTED, actual);
        }
    }
}
