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
    /// <summary>Exception tests for the PasswordHash class</summary>
    [TestFixture]
    public class PasswordHashExceptionTest
    {
        [Test]
        public void ScryptHashStringNoPassword()
        {
            const long OPS_LIMIT = 481326;
            const int MEM_LIMIT = 7256678;
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                Scrypt.ScryptHashString(null, OPS_LIMIT, MEM_LIMIT);
            });
        }

        [Test]
        public void ScryptHashStringBadOpsLimit()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const int MEM_LIMIT = 7256678;
            Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            {
                Scrypt.ScryptHashString(PASSWORD, 0, MEM_LIMIT);
            });
        }

        [Test]
        public void ScryptHashStringBadMemLimit()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const long OPS_LIMIT = 481326;
            Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            {
                Scrypt.ScryptHashString(PASSWORD, OPS_LIMIT, 0);
            });
        }

        [Test, Ignore("not implemented")]
        public void ScryptHashStringOutOfMemory()
        {
            //TODO: implement (should work on any testsystem)
            //Note: Int32.MaxValue
            _ = Assert.Throws<System.OutOfMemoryException>(() =>
              {

              });
        }

        [Test]
        public void ScryptHashBinaryNoPassword()
        {
            const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
            const long OUTPUT_LENGTH = 32;
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                Scrypt.ScryptHashBinary(null, SALT, Scrypt.Strength.Interactive, OUTPUT_LENGTH);
            });
        }

        [Test]
        public void ScryptHashBinaryNoSalt()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const long OUTPUT_LENGTH = 32;
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                Scrypt.ScryptHashBinary(PASSWORD, null, Scrypt.Strength.Interactive, OUTPUT_LENGTH);
            });
        }

        [Test]
        public void ScryptHashBinaryWrongSaltLength()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const string SALT = "qa~t](84z<1t";
            const long OUTPUT_LENGTH = 32;
            Assert.Throws<SaltOutOfRangeException>(() =>
            {
                Scrypt.ScryptHashBinary(PASSWORD, SALT, Scrypt.Strength.Interactive, OUTPUT_LENGTH);
            });
        }

        [Test]
        public void ScryptHashBinaryBadOpsLimit()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
            const long OUTPUT_LENGTH = 32;
            const long OPS_LIMIT = 0;
            const int MEM_LIMIT = 7256678;
            Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            {
                Scrypt.ScryptHashBinary(PASSWORD, SALT, OPS_LIMIT, MEM_LIMIT, OUTPUT_LENGTH);
            });
        }

        [Test]
        public void ScryptHashBinaryBadMemLimit()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
            const long OUTPUT_LENGTH = 32;
            const long OPS_LIMIT = 481326;
            const int MEM_LIMIT = 0;
            Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            {
                Scrypt.ScryptHashBinary(PASSWORD, SALT, OPS_LIMIT, MEM_LIMIT, OUTPUT_LENGTH);
            });
        }

        [Test]
        public void ScryptHashBinaryBadOutputLength()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
            const long OUTPUT_LENGTH = 0;
            const long OPS_LIMIT = 481326;
            const int MEM_LIMIT = 7256678;
            Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            {
                Scrypt.ScryptHashBinary(PASSWORD, SALT, OPS_LIMIT, MEM_LIMIT, OUTPUT_LENGTH);
            });
        }

        [Test, Ignore("not implemented")]
        public void ScryptHashBinaryOutOfMemory()
        {
            //TODO: implement (should work on any testsystem)
            //Note: Int32.MaxValue
            _ = Assert.Throws<System.OutOfMemoryException>(() =>
              {

              });
        }

        [Test]
        public void ScryptHashStringVerifyNoHash()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                Scrypt.ScryptHashStringVerify(null, PASSWORD);
            });
        }

        [Test]
        public void ScryptHashStringVerifyNoPassword()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                var hash = Scrypt.ScryptHashString(PASSWORD);
                Scrypt.ScryptHashStringVerify(hash, null);
            });
        }

    }
}
