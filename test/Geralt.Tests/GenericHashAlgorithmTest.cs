using Geralt;
using NUnit.Framework;
using System.IO;
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
    class GenericHashAlgorithmTest
    {
        /// <summary>BLAKE2b, 32 bytes, with key, from byte array</summary>
        [Test]
        public void ComputeHashFromBytes()
        {
            var expected = Utilities.HexToBinary("8866267f985204ae511980704ac85ec4936ee535c37541f342976b2cb3ac62fd");
            var hashStream = new BLAKE2b.GenericHashAlgorithm("This is a test key", 32);
            var actual = hashStream.ComputeHash(Encoding.UTF8.GetBytes("Adam Caudill"));
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>BLAKE2b, 32 bytes, with key, from empty stream</summary>
        [Test]
        public void ComputeHashFromNullStream()
        {
            var expected = Utilities.HexToBinary("4afd15412c1b940d7cffc9049b9ed413cbaeb626aca2a70c2afbeea7a85bdf8e");
            var stream = Stream.Null;
            var hashStream = new BLAKE2b.GenericHashAlgorithm("This is a test key", 32);
            var actual = hashStream.ComputeHash(stream);
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>BLAKE2b, 32 bytes, with key, from memory stream</summary>
        [Test]
        public void ComputeHashFromMemoryStream()
        {
            var expected = Utilities.HexToBinary("8866267f985204ae511980704ac85ec4936ee535c37541f342976b2cb3ac62fd");
            var stream = new MemoryStream(Encoding.UTF8.GetBytes("Adam Caudill"));
            var hashStream = new BLAKE2b.GenericHashAlgorithm("This is a test key", 32);
            var actual = hashStream.ComputeHash(stream);
            CollectionAssert.AreEqual(expected, actual);
        }
    }
}
