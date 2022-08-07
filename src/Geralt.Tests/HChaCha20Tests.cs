using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class HChaCha20Tests
{
    // draft-irtf-cfrg-xchacha Section 2.2.1: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#section-2.2.1
    private static readonly byte[] Output = Convert.FromHexString("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    private static readonly byte[] Key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] Nonce = Convert.FromHexString("000000090000004a0000000031415927");
    
    [TestMethod]
    public void DeriveKey_ValidInputs()
    {
        Span<byte> output = stackalloc byte[HChaCha20.OutputSize];
        HChaCha20.DeriveKey(output, Key, Nonce);
        Assert.IsTrue(output.SequenceEqual(Output));
    }
    
    [TestMethod]
    public void DeriveKey_DifferentKey()
    {
        Span<byte> output = stackalloc byte[HChaCha20.OutputSize];
        Span<byte> key = Key.ToArray();
        key[0]++;
        HChaCha20.DeriveKey(output, key, Nonce);
        Assert.IsFalse(output.SequenceEqual(Output));
    }
    
    [TestMethod]
    public void DeriveKey_DifferentNonce()
    {
        Span<byte> output = stackalloc byte[HChaCha20.OutputSize];
        Span<byte> nonce = Nonce.ToArray();
        nonce[0]++;
        HChaCha20.DeriveKey(output, Key, nonce);
        Assert.IsFalse(output.SequenceEqual(Output));
    }
    
    [TestMethod]
    public void DeriveKey_DifferentPersonalisation()
    {
        Span<byte> output = stackalloc byte[HChaCha20.OutputSize];
        Span<byte> personalisation = Encoding.UTF8.GetBytes("!Cahir Ceallach!");
        HChaCha20.DeriveKey(output, Key, Nonce, personalisation);
        Assert.IsFalse(output.SequenceEqual(Output));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidOutput()
    {
        var output = new byte[HChaCha20.OutputSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaCha20.DeriveKey(output, Key, Nonce));
        output = new byte[HChaCha20.OutputSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaCha20.DeriveKey(output, Key, Nonce));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidKey()
    {
        var output = new byte[HChaCha20.OutputSize];
        var key = new byte[HChaCha20.KeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaCha20.DeriveKey(output, key, Nonce));
        key = new byte[HChaCha20.KeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaCha20.DeriveKey(output, key, Nonce));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidNonce()
    {
        var output = new byte[HChaCha20.OutputSize];
        var nonce = new byte[HChaCha20.NonceSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaCha20.DeriveKey(output, Key, nonce));
        nonce = new byte[HChaCha20.NonceSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaCha20.DeriveKey(output, Key, nonce));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidPersonalisation()
    {
        var output = new byte[HChaCha20.OutputSize];
        var personalisation = new byte[HChaCha20.PersonalSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaCha20.DeriveKey(output, Key, Nonce, personalisation));
        personalisation = new byte[HChaCha20.PersonalSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaCha20.DeriveKey(output, Key, Nonce, personalisation));
    }
}