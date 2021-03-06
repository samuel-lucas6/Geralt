using Geralt;
using Geralt.Exceptions;
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
    /// <summary>Exception tests for the PublicKeyBox class</summary>
    [TestFixture]
    public class PublicKeyBoxExceptionTest
    {
        [Test]
        public void GenerateKeyPairFromPrivateBadKeyTest()
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
              () => AuthenticatedHybridEncryption.GenerateKeyPair(bobSk));
        }

        [Test]
        public void GenerateKeyPairFromPrivateBadSeedTest()
        {
            //30 byte
            var invalidSeed = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            _ = Assert.Throws<SeedOutOfRangeException>(
              () => AuthenticatedHybridEncryption.GenerateSeededKeyPair(invalidSeed));
        }

        [Test]
        public void PublicKeyBoxCreateWithBadPrivateKey()
        {
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");
            var nonce = Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX");
            var alicePk = Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645");

            _ = Assert.Throws<KeyOutOfRangeException>(
              () => AuthenticatedHybridEncryption.Create(message, nonce, bobSk, alicePk));
        }

        [Test]
        public void PublicKeyBoxCreateWithBadPublicKey()
        {
            var bobPk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");
            var nonce = Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX");
            var aliceSk = Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975");

            _ = Assert.Throws<KeyOutOfRangeException>(
              () => AuthenticatedHybridEncryption.Create(message, nonce, aliceSk, bobPk));
        }

        [Test]
        public void PublicKeyBoxCreateWithBadNonce()
        {
            var message = Encoding.UTF8.GetBytes("Adam Caudill");
            var nonce = Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVX");
            var bobSk = Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975");
            var alicePk = Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645");

            _ = Assert.Throws<NonceOutOfRangeException>(
              () => AuthenticatedHybridEncryption.Create(message, nonce, bobSk, alicePk));
        }

        [Test]
        public void PublicKeyBoxCreateDetachedWithBadPrivateKey()
        {
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");
            var nonce = Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX");
            var alicePk = Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645");

            _ = Assert.Throws<KeyOutOfRangeException>(
              () => AuthenticatedHybridEncryption.CreateDetached(message, nonce, bobSk, alicePk));
        }

        [Test]
        public void PublicKeyBoxCreateDetachedWithBadPublicKey()
        {
            var bobPk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");
            var nonce = Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX");
            var aliceSk = Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975");

            _ = Assert.Throws<KeyOutOfRangeException>(
              () => AuthenticatedHybridEncryption.CreateDetached(message, nonce, aliceSk, bobPk));
        }

        [Test]
        public void PublicKeyBoxCreateDetachedWithBadNonce()
        {
            _ = Assert.Throws<NonceOutOfRangeException>(() =>
              {
                  _ = AuthenticatedHybridEncryption.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVX"),
              Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
              Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));
              });
        }

        [Test]
        public void PublicKeyBoxOpenBadPrivateKey()
        {
            var bobPk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = AuthenticatedHybridEncryption.Open(
              Utilities.HexToBinary("aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              bobPk,
              Utilities.HexToBinary("753cb95919b15b76654b1969c554a4aaf8334402ef1468cb40a602b9c9fd2c13"));
              });
        }

        [Test]
        public void PublicKeyBoxOpenBadPublicKey()
        {
            var bobPk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };

            _ = Assert.Throws<KeyOutOfRangeException>(() =>
              {
                  _ = AuthenticatedHybridEncryption.Open(
              Utilities.HexToBinary("aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Utilities.HexToBinary("d4c8438482d5d103a2315251a5eed7c46017864a02ddc4c8b03f0ede8cb3ef9b"), bobPk);
              });

        }

        [Test]
        public void PublicKeyBoxOpenBadNonce()
        {
            _ = Assert.Throws<NonceOutOfRangeException>(() =>
              {
                  _ = AuthenticatedHybridEncryption.Open(
              Utilities.HexToBinary("aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
              Utilities.HexToBinary("d4c8438482d5d103a2315251a5eed7c46017864a02ddc4c8b03f0ede8cb3ef9b"),
              Utilities.HexToBinary("753cb95919b15b76654b1969c554a4aaf8334402ef1468cb40a602b9c9fd2c13"));
              });
        }

        [Test]
        public void PublicKeyBoxOpenDetachedBadPrivateKey()
        {
            var actual = AuthenticatedHybridEncryption.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
              Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                AuthenticatedHybridEncryption.OpenDetached(actual.Ciphertext, actual.Mac,
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
            Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a159"),
            Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));
            });
        }

        [Test]
        public void PublicKeyBoxOpenDetachedBadPublicKey()
        {
            var actual = AuthenticatedHybridEncryption.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
              Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                AuthenticatedHybridEncryption.OpenDetached(actual.Ciphertext, actual.Mac,
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
            Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
            Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec856"));
            });
        }

        [Test]
        public void PublicKeyBoxOpenDetachedBadNonce()
        {
            var actual = AuthenticatedHybridEncryption.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
              Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

            Assert.Throws<NonceOutOfRangeException>(() =>
            {
                AuthenticatedHybridEncryption.OpenDetached(actual.Ciphertext, actual.Mac,
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
            Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
            Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));
            });
        }


        [Test]
        public void PublicKeyBoxOpenDetachedBadMac()
        {
            var actual = AuthenticatedHybridEncryption.CreateDetached(
            Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
            Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
            Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

            _ = Assert.Throws<TagOutOfRangeException>(() =>
              {
                  _ = AuthenticatedHybridEncryption.OpenDetached(actual.Ciphertext, null,
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
              Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));
              });
        }
    }
}
