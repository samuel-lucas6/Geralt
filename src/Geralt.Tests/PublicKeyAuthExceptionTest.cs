using Geralt;
using Geralt.Exceptions;
using NUnit.Framework;
using System.Security.Cryptography;
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
    /// <summary>Exception tests for the PublicKeyAuth class</summary>
    [TestFixture]
    public class PublicKeyAuthExceptionTest
    {
        [Test]
        public void GenerateKeyPairWithBadSeed()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };

            _ = Assert.Throws<SeedOutOfRangeException>(
              () => Ed25519.GenerateKeyPair(bobSk));
        }

        [Test]
        public void SignAuthBadKey()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");

            _ = Assert.Throws<KeyOutOfRangeException>(
              () => Ed25519.Sign(message, bobSk));
        }

        [Test]
        public void VerifyAuthBadKey()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");

            _ = Assert.Throws<KeyOutOfRangeException>(
              () => Ed25519.Verify(message, bobSk));
        }

        [Test]
        public void VerifyAuthWrongKey()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88,0x88,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");

            //It`s not really signed ...
            _ = Assert.Throws<CryptographicException>(
              () => Ed25519.Verify(message, bobSk));
        }

        [Test]
        public void SignAuthDetachedBadKey()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");

            _ = Assert.Throws<KeyOutOfRangeException>(
              () => Ed25519.SignDetached(message, bobSk));
        }

        [Test]
        public void VerifyAuthDetachedBadKey()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var signature = Utilities.HexToBinary("8d5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b");
            var message = Encoding.UTF8.GetBytes("Adam Caudill");

            _ = Assert.Throws<KeyOutOfRangeException>(
              () => Ed25519.VerifyDetached(signature, message, bobSk));
        }

        [Test]
        public void VerifyAuthDetachedBadSignature()
        {
            var signature = Utilities.HexToBinary("5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b");
            var message = Encoding.UTF8.GetBytes("Adam Caudill");
            var key = Utilities.HexToBinary("4ffda13c11d61d2b9568e54bec06ea59368e84874883087645e64e5e9653422e");
            _ = Assert.Throws<SignatureOutOfRangeException>(
              () => Ed25519.VerifyDetached(signature, message, key));
        }

        [Test]
        public void ConvertEd25519PublicKeyToCurve25519PublicKeyBadKey()
        {
            //Don`t copy keypairSeed for other tests (bad key)!
            //30 byte
            var keypairSeed = new byte[]{
        0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde,
        0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a, 0xed, 0xae,
        0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe,
        0x4d, 0x14, 0x51, 0xa5, 0x59, 0xfa
      };

            Assert.Throws<KeyOutOfRangeException>(
              () => Ed25519.ConvertEd25519PublicKeyToCurve25519PublicKey(keypairSeed));
        }

        [Test, Ignore("not implemented")]
        public void ConvertEd25519PublicKeyToCurve25519PublicKeyWrongKey()
        {
            //TODO: implement
            _ = Assert.Throws<CryptographicException>(() =>
              {

              });
        }

        [Test]
        public void ConvertEd25519SecretKeyToCurve25519SecretKeyBadKey()
        {
            //Don`t copy keypairSeed for other tests (bad key)!
            //62 byte
            var keypairSeed = new byte[]{
        0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde,
        0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a, 0xed, 0xae,
        0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe,
        0x4d, 0x14, 0x51, 0xa5, 0x59, 0xfa, 0xea, 0xde,
        0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde,
        0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a, 0xed, 0xae,
        0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe,
        0x4d, 0x14, 0x51, 0xa5, 0x59, 0xfa
      };

            Assert.Throws<KeyOutOfRangeException>(
              () => Ed25519.ConvertEd25519SecretKeyToCurve25519SecretKey(keypairSeed));
        }

        [Test, Ignore("not implemented")]
        public void ConvertEd25519SecretKeyToCurve25519SecretKeyWrongKey()
        {
            //TODO: implement
            _ = Assert.Throws<CryptographicException>(() =>
              {

              });
        }
    }
}
