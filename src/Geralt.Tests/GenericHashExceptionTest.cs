using Geralt;
using Geralt.Exceptions;
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
    /// <summary>Exception tests for the GenericHash class</summary>
    [TestFixture]
    public class GenericHashExceptionTest
    {
        [Test]
        public void GenericHashKeyTooLong()
        {
            const string KEY = "1234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456";
            const int BYTES = 32;
            _ = Assert.Throws<KeyOutOfRangeException>(() => BLAKE2b.Hash("Adam Caudill", KEY, BYTES));
        }

        [Test]
        public void GenericHashKeyTooShort()
        {
            const string KEY = "12345";
            const int BYTES = 32;
            _ = Assert.Throws<KeyOutOfRangeException>(() => BLAKE2b.Hash("Adam Caudill", KEY, BYTES));
        }

        [Test]
        public void GenericHashBytesTooLong()
        {
            const string KEY = "1234567891123456";
            const int BYTES = 128;
            _ = Assert.Throws<BytesOutOfRangeException>(() => BLAKE2b.Hash("Adam Caudill", KEY, BYTES));
        }

        [Test]
        public void GenericHashBytesTooShort()
        {
            const string KEY = "1234567891123456";
            const int BYTES = 12;
            _ = Assert.Throws<BytesOutOfRangeException>(() => BLAKE2b.Hash("Adam Caudill", KEY, BYTES));
        }

        [Test]
        public void GenericHashSaltPersonalNoMessage()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            _ = Assert.Throws<System.ArgumentNullException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal(null, KEY, SALT, PERSONAL));
              });
        }

        [Test]
        public void GenericHashSaltPersonalNoSalt()
        {
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            _ = Assert.Throws<System.ArgumentNullException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, null, PERSONAL));
              });
        }

        [Test]
        public void GenericHashSaltPersonalNoPersonal()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string KEY = "1234567891123456";
            _ = Assert.Throws<System.ArgumentNullException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, null));
              });
        }

        [Test]
        public void GenericHashSaltPersonalKeyTooLong()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456";
            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, PERSONAL));
              });
        }

        [Test]
        public void GenericHashSaltPersonalKeyTooShort()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "12345";
            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, PERSONAL));
              });
        }

        [Test]
        public void GenericHashSaltPersonalSaltTooLong()
        {
            const string SALT = "5b6b41ed9b343fe05b6b41ed9b343fe05b6b41ed9b343fe05b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            _ = Assert.Throws<SaltOutOfRangeException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, PERSONAL));
              });
        }

        [Test]
        public void GenericHashSaltPersonalSaltTooShort()
        {
            const string SALT = "5b6b";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            _ = Assert.Throws<SaltOutOfRangeException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, PERSONAL));
              });
        }

        [Test]
        public void GenericHashSaltPersonalPersonalTooLong()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a5126fb2a37400d2a5126fb2a37400d2a5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            _ = Assert.Throws<PersonalOutOfRangeException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, PERSONAL));
              });
        }

        [Test]
        public void GenericHashSaltPersonalPersonalTooShort()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126f";
            const string KEY = "1234567891123456";
            _ = Assert.Throws<PersonalOutOfRangeException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, PERSONAL));
              });
        }

        [Test]
        public void GenericHashSaltPersonalBytesTooShort()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            _ = Assert.Throws<BytesOutOfRangeException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, PERSONAL, 5));
              });
        }

        [Test]
        public void GenericHashSaltPersonalBytesTooLong()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            _ = Assert.Throws<BytesOutOfRangeException>(() =>
              {
                  _ = Utilities.BinaryToHex(BLAKE2b.HashSaltPersonal("message", KEY, SALT, PERSONAL, 128));
              });
        }
    }
}
