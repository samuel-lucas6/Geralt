using Geralt;
using NUnit.Framework;
using System;

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
    /// <summary>Exception tests for the Utilities class</summary>
    [TestFixture]
    public class UtilitiesExceptionTest
    {
        //TODO: implement, but first change the Exception types in HexBinary and Binary2Hex, because they are bad :)

        [Test]
        public void BinaryToBase64NullTest()
        {
            Assert.That(() => Utilities.BinaryToBase64(null),
              Throws.Exception.TypeOf<ArgumentNullException>());
        }

        [Test]
        public void Base64ToBinaryNullTest()
        {
            Assert.That(() => Utilities.Base64ToBinary(null, " "),
              Throws.Exception.TypeOf<ArgumentNullException>());
        }
    }
}
