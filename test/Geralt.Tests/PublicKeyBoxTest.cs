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
    /// <summary>Tests for the PublicKeyBox class</summary>
    [TestFixture]
    public class PublicKeyBoxTest
    {
        // Test Key 1:
        //  Public Key: 753cb95919b15b76654b1969c554a4aaf8334402ef1468cb40a602b9c9fd2c13
        //  Private Key: 2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975
        //
        // Test Key 2:
        //  Public Key: 83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645
        //  Private Key: d4c8438482d5d103a2315251a5eed7c46017864a02ddc4c8b03f0ede8cb3ef9b

        /// <summary>Keys must not be null and size is 32</summary>
        [Test]
        public void GenerateKeyPairTest()
        {
            var aliceKeypair = PublicKeyBox.GenerateKeyPair();

            Assert.IsNotNull(aliceKeypair.PrivateKey);
            Assert.IsNotNull(aliceKeypair.PublicKey);

            Assert.AreEqual(32, aliceKeypair.PrivateKey.Length);
            Assert.AreEqual(32, aliceKeypair.PublicKey.Length);
        }

        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateNonce()
        {
            Assert.AreEqual(24, PublicKeyBox.GenerateNonce().Length);
        }

        /// <summary>Does PublicKeyBox.GenerateKeyPair(privateKey) return the rigt public key</summary>
        [Test]
        public void GenerateKeyPairFromPrivateTest()
        {
            var actual = PublicKeyBox.GenerateKeyPair(Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"));

            CollectionAssert.AreEqual(Utilities.HexToBinary("753cb95919b15b76654b1969c554a4aaf8334402ef1468cb40a602b9c9fd2c13"), actual.PublicKey);
        }

        /// <summary>Does PublicKeyBox.GenerateSeededKeyPair(seed) return the rigt deterministic public key</summary>
        [Test]
        public void GenerateDeterministicPublicKeyFromSeedTest()
        {
            var actual = PublicKeyBox.GenerateSeededKeyPair(Utilities.HexToBinary("0b93e7914224f0e7de0984ce6480020e7f11c37c35e967399625b6186202275c"));

            CollectionAssert.AreEqual(Utilities.HexToBinary("309db6bd8e8fc75d0beda31c8273d572541784f1d566f877aeedda5c4cb87514"), actual.PublicKey);
        }

        /// <summary>Does PublicKeyBox.GenerateSeededKeyPair(seed) return the rigt deterministic private key</summary>
        [Test]
        public void GenerateDeterministicPrivateKeyFromSeedTest()
        {
            var actual = PublicKeyBox.GenerateSeededKeyPair(Utilities.HexToBinary("0b93e7914224f0e7de0984ce6480020e7f11c37c35e967399625b6186202275c"));

            CollectionAssert.AreEqual(Utilities.HexToBinary("082f8b811ca316a1fa22d40a19c7cba91a814d73a333c752d508efd3be2d58db"), actual.PrivateKey);
        }

        /// <summary>Does PublicKeyBox.Create creates the right data?</summary>
        [Test]
        public void SimpleCreateTest()
        {
            var expected = Utilities.HexToBinary("aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d");
            var actual = PublicKeyBox.Create(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
              Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does PublicKeyBox.Open() return the expected value?</summary>
        [Test]
        public void SimpleOpenTest()
        {
            var expected = Encoding.UTF8.GetBytes("Adam Caudill");
            var actual = PublicKeyBox.Open(
              Utilities.HexToBinary("aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Utilities.HexToBinary("d4c8438482d5d103a2315251a5eed7c46017864a02ddc4c8b03f0ede8cb3ef9b"),
              Utilities.HexToBinary("753cb95919b15b76654b1969c554a4aaf8334402ef1468cb40a602b9c9fd2c13"));

            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does PublicKeyBox.Open() return the expected value when including extra padding from old versions?</summary>
        [Test]
        public void SimpleLegacyOpenTest()
        {
            var expected = Encoding.UTF8.GetBytes("Adam Caudill");
            var actual = PublicKeyBox.Open(
              Utilities.HexToBinary("00000000000000000000000000000000aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Utilities.HexToBinary("d4c8438482d5d103a2315251a5eed7c46017864a02ddc4c8b03f0ede8cb3ef9b"),
              Utilities.HexToBinary("753cb95919b15b76654b1969c554a4aaf8334402ef1468cb40a602b9c9fd2c13"));

            CollectionAssert.AreEqual(expected, actual);
        }

        [Test]
        public void DetachedBox()
        {
            var expected = Utilities.HexToBinary("4164616d2043617564696c6c");
            var actual = PublicKeyBox.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
              Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

            var clear = PublicKeyBox.OpenDetached(actual.CipherText, actual.Mac,
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
              Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

            Assert.AreEqual(clear, expected);
        }
    }
}
