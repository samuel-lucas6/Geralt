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
    /// <summary>Tests for the PublicKeyAuth class</summary>
    [TestFixture]
    public class PublicKeyAuthTest
    {
        /// <summary>Does PublicKeyAuth.GenerateKeyPair() return... something.</summary>
        [Test]
        public void GenerateKeyTest()
        {
            var actual = Ed25519.GenerateKeyPair();

            //need a better test
            Assert.IsNotNull(actual.PrivateKey);
            Assert.IsNotNull(actual.PublicKey);
        }

        [Test]
        public void GenerateKeyVerifySignedDataTest()
        {
            var actual = Ed25519.GenerateKeyPair();
            byte[] randomArray = SecureRandom.GetBytes(255);
            var sign = Ed25519.SignDetached(randomArray, actual.PrivateKey);
            Assert.IsTrue(Ed25519.VerifyDetached(sign, randomArray, actual.PublicKey));
        }

        /// <summary>Does PublicKeyAuth.GenerateKeyPair(seed) return the expected value?</summary>
        [Test]
        public void GenerateKeySeedTest()
        {
            var expected = new KeyPair(Utilities.HexToBinary("76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5"),
              Utilities.HexToBinary("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5"));
            var actual = Ed25519.GenerateKeyPair(Utilities.HexToBinary("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

            CollectionAssert.AreEqual(expected.PublicKey, actual.PublicKey);
            CollectionAssert.AreEqual(expected.PrivateKey, actual.PrivateKey);
        }

        /// <summary>Does PublicKeyAuth.Sign() return the expected value?</summary>
        [Test]
        public void SimpleAuthTest()
        {
            var expected = Utilities.HexToBinary("8d5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b4164616d2043617564696c6c");
            var actual = Ed25519.Sign(Encoding.UTF8.GetBytes("Adam Caudill"),
              Utilities.HexToBinary("89dff97c131434c11809c3341510ce63c85e851d3ba62e2f810016bbc67d35144ffda13c11d61d2b9568e54bec06ea59368e84874883087645e64e5e9653422e"));
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does SecretKeyAuth.Verify() return the expected value?</summary>
        [Test]
        public void SimpleVerifyTest()
        {
            var expected = Encoding.UTF8.GetBytes("Adam Caudill");
            var actual = Ed25519.Verify(Utilities.HexToBinary("8d5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b4164616d2043617564696c6c"),
              Utilities.HexToBinary("4ffda13c11d61d2b9568e54bec06ea59368e84874883087645e64e5e9653422e"));
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does PublicKeyAuth.SignDetached() return the expected value?</summary>
        [Test]
        public void SimpleAuthDetachedTest()
        {
            var expected = Utilities.HexToBinary("8d5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b");
            var actual = Ed25519.SignDetached(Encoding.UTF8.GetBytes("Adam Caudill"),
              Utilities.HexToBinary("89dff97c131434c11809c3341510ce63c85e851d3ba62e2f810016bbc67d35144ffda13c11d61d2b9568e54bec06ea59368e84874883087645e64e5e9653422e"));
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does SecretKeyAuth.VerifyDetached() return the expected value?</summary>
        [Test]
        public void SimpleVerifyDetachedTest()
        {
            var actual = Ed25519.VerifyDetached(
              Utilities.HexToBinary("8d5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b"),
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Utilities.HexToBinary("4ffda13c11d61d2b9568e54bec06ea59368e84874883087645e64e5e9653422e"));

            Assert.IsTrue(actual);
        }

        [Test]
        public void ExtractEd25519SeedFromEd25519SecretKeyTest()
        {
            // generate an Ed25519 keypair
            var firstKeypair = Ed25519.GenerateKeyPair();
            // extract the seed from the generated keypair
            var seed = Ed25519.ExtractEd25519SeedFromEd25519SecretKey(firstKeypair.PrivateKey);
            // generate a second keypair from the seed
            var secondKeyPair = Ed25519.GenerateKeyPair(seed);
            CollectionAssert.AreEqual(firstKeypair.PublicKey, secondKeyPair.PublicKey);
            CollectionAssert.AreEqual(firstKeypair.PrivateKey, secondKeyPair.PrivateKey);
        }

        [Test]
        public void ExtractEd25519PublicKeyFromEd25519SecretKey()
        {
            // generate an Ed25519 keypair
            var keypair = Ed25519.GenerateKeyPair();
            // extract the seed from the generated keypair
            var publicKey = Ed25519.ExtractEd25519PublicKeyFromEd25519SecretKey(keypair.PrivateKey);
            CollectionAssert.AreEqual(keypair.PublicKey, publicKey);
        }

        [Test]
        public void PublicKeyAuthConvertToCurve25519()
        {
            var keypairSeed = new byte[]{
        0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde,
        0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a, 0xed, 0xae,
        0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe,
        0x4d, 0x14, 0x51, 0xa5, 0x59, 0xfa, 0xed, 0xee
      };

            var keys = Ed25519.GenerateKeyPair(keypairSeed);

            var ed25519Pk = keys.PublicKey;
            var ed25519SkPk = keys.PrivateKey;

            var curve25519Pk = Ed25519.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519Pk);
            var curve25519Sk = Ed25519.ConvertEd25519SecretKeyToCurve25519SecretKey(ed25519SkPk);

            Assert.AreEqual(Utilities.BinaryToHex(curve25519Pk, Utilities.HexFormat.None, Utilities.HexCase.Upper),
                            "F1814F0E8FF1043D8A44D25BABFF3CEDCAE6C22C3EDAA48F857AE70DE2BAAE50");
            Assert.AreEqual(Utilities.BinaryToHex(curve25519Sk, Utilities.HexFormat.None, Utilities.HexCase.Upper),
                            "8052030376D47112BE7F73ED7A019293DD12AD910B654455798B4667D73DE166");

            for (var i = 0; i < 500; i++)
            {
                keys = Ed25519.GenerateKeyPair();
                ed25519Pk = keys.PublicKey;
                ed25519SkPk = keys.PrivateKey;
                curve25519Pk = Ed25519.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519Pk);
                curve25519Sk = Ed25519.ConvertEd25519SecretKeyToCurve25519SecretKey(ed25519SkPk);
                var curve25519Pk2 = X25519.Base(curve25519Sk);

                CollectionAssert.AreEqual(curve25519Pk, curve25519Pk2);
            }
        }
    }
}
