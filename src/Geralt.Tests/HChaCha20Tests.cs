using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class HChaCha20Tests
{
    [TestMethod]
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#section-2.2.1
    [DataRow("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000090000004a0000000031415927")]
    public void DeriveKey_Valid(string output, string key, string nonce)
    {
        Span<byte> okm = stackalloc byte[HChaCha20.OutputSize];
        Span<byte> ikm = Convert.FromHexString(key);
        Span<byte> npub = Convert.FromHexString(nonce);
        
        HChaCha20.DeriveKey(okm, ikm, npub);
        
        Assert.AreEqual(output, Convert.ToHexString(okm).ToLower());
    }
    
    [TestMethod]
    [DataRow(HChaCha20.OutputSize + 1, HChaCha20.KeySize, HChaCha20.NonceSize, HChaCha20.PersonalSize)]
    [DataRow(HChaCha20.OutputSize - 1, HChaCha20.KeySize, HChaCha20.NonceSize, HChaCha20.PersonalSize)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize + 1, HChaCha20.NonceSize, HChaCha20.PersonalSize)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize - 1, HChaCha20.NonceSize, HChaCha20.PersonalSize)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize, HChaCha20.NonceSize + 1, HChaCha20.PersonalSize)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize, HChaCha20.NonceSize - 1, HChaCha20.PersonalSize)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize, HChaCha20.NonceSize, HChaCha20.PersonalSize + 1)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize, HChaCha20.NonceSize, HChaCha20.PersonalSize - 1)]
    public void DeriveKey_Invalid(int outputSize, int keySize, int nonceSize, int personalisationSize)
    {
        var okm = new byte[outputSize];
        var ikm = new byte[keySize];
        var npub = new byte[nonceSize];
        var ctx = new byte[personalisationSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaCha20.DeriveKey(okm, ikm, npub, ctx));
    }
}