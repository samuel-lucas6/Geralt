using Geralt;
using NUnit.Framework;

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
    /// <summary>Tests for Random Numbers support</summary>
    [TestFixture]
    public class RandomNumbersTest
    {
        /// <summary>Does SodiumCore.GetRandomNumber() return something</summary>
        [Test]
        public void GetRandomNumbersTest()
        {
            var n1 = GeraltCore.GetRandomNumber(1600);
            var n2 = GeraltCore.GetRandomNumber(25550);
            var n3 = GeraltCore.GetRandomNumber(5);
            var n4 = GeraltCore.GetRandomNumber(2147483647);
            var n5 = GeraltCore.GetRandomNumber(0); //always 0

            Assert.IsNotNull(n1);
            Assert.IsNotNull(n2);
            Assert.IsNotNull(n3);
            Assert.IsNotNull(n4);
            Assert.IsNotNull(n5);

            Assert.Less(n1, 1600);
            Assert.Less(n2, 25550);
            Assert.Less(n3, 5);
            Assert.Less(n4, 2147483647);
            Assert.AreEqual(n5, 0);
        }
    }
}
