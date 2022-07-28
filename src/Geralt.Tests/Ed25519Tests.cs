using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class Ed25519Tests
{
    /// RFC 8032 Section 7.1: https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1
    private static readonly byte[] AlicePrivateKey = Convert.FromHexString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    private static readonly byte[] AlicePublicKey = Convert.FromHexString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    private static readonly byte[] Message = Convert.FromHexString("72");
    private static readonly byte[] Signature = Convert.FromHexString("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    // Generated using libsodium-core
    private static readonly byte[] X25519PrivateKey = Convert.FromHexString("68bd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e51");
    private static readonly byte[] X25519PublicKey = Convert.FromHexString("25c704c594b88afc00a76b69d1ed2b984d7e22550f3ed0802d04fbcd07d38d47");
    private static readonly byte[] Seed = Convert.FromHexString("b589764bb6395e13788436f93f4eaa4c858900b6a12328e8626ded5b39d2c7e9");
    private static readonly byte[] EvePrivateKey = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    private static readonly byte[] EvePublicKey = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    
    [TestMethod]
    public void GenerateKeyPair_ValidInputs()
    {
        Span<byte> publicKey = stackalloc byte[Ed25519.PublicKeySize];
        Span<byte> privateKey = stackalloc byte[Ed25519.PrivateKeySize];
        Ed25519.GenerateKeyPair(publicKey, privateKey);
        Assert.IsFalse(publicKey.SequenceEqual(new byte[publicKey.Length]));
        Assert.IsFalse(privateKey.SequenceEqual(new byte[privateKey.Length]));
    }
    
    [TestMethod]
    public void GenerateKeyPair_InvalidPublicKey()
    {
        var publicKey = new byte[Ed25519.PublicKeySize - 1];
        var privateKey = new byte[Ed25519.PrivateKeySize];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(publicKey, privateKey));
        publicKey = new byte[Ed25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(publicKey, privateKey));
    }
    
    [TestMethod]
    public void GenerateKeyPair_InvalidPrivateKey()
    {
        var publicKey = new byte[Ed25519.PublicKeySize];
        var privateKey = new byte[Ed25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(publicKey, privateKey));
        privateKey = new byte[Ed25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(publicKey, privateKey));
    }
    
    [TestMethod]
    public void GenerateSeededKeyPair_ValidInputs()
    {
        Span<byte> publicKey = stackalloc byte[Ed25519.PublicKeySize];
        Span<byte> privateKey = stackalloc byte[Ed25519.PrivateKeySize];
        Ed25519.GenerateKeyPair(publicKey, privateKey, Seed);
        Assert.IsFalse(publicKey.SequenceEqual(new byte[publicKey.Length]));
        Assert.IsFalse(privateKey.SequenceEqual(new byte[privateKey.Length]));
    }
    
    [TestMethod]
    public void GenerateSeededKeyPair_InvalidPublicKey()
    {
        var publicKey = new byte[Ed25519.PublicKeySize - 1];
        var privateKey = new byte[Ed25519.PrivateKeySize];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(publicKey, privateKey, Seed));
        publicKey = new byte[Ed25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(publicKey, privateKey, Seed));
    }
    
    [TestMethod]
    public void GenerateSeededKeyPair_InvalidPrivateKey()
    {
        var publicKey = new byte[Ed25519.PublicKeySize];
        var privateKey = new byte[Ed25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(publicKey, privateKey, Seed));
        privateKey = new byte[Ed25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(publicKey, privateKey, Seed));
    }
    
    [TestMethod]
    public void GenerateSeededKeyPair_InvalidSeed()
    {
        var publicKey = new byte[Ed25519.PublicKeySize];
        var privateKey = new byte[Ed25519.PrivateKeySize];
        var seed = new byte[Ed25519.SeedSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(publicKey, privateKey, seed));
        seed = new byte[Ed25519.SeedSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(publicKey, privateKey, seed));
    }
    
    [TestMethod]
    public void ComputePublicKey_ValidInputs()
    {
        Span<byte> publicKey = stackalloc byte[Ed25519.PublicKeySize];
        Ed25519.ComputePublicKey(publicKey, AlicePrivateKey);
        Assert.IsTrue(publicKey.SequenceEqual(AlicePublicKey));
    }
    
    [TestMethod]
    public void ComputePublicKey_DifferentPrivateKey()
    {
        Span<byte> publicKey = stackalloc byte[Ed25519.PublicKeySize];
        Ed25519.ComputePublicKey(publicKey, EvePrivateKey);
        Assert.IsFalse(publicKey.SequenceEqual(AlicePublicKey));
    }
    
    [TestMethod]
    public void ComputePublicKey_InvalidPublicKey()
    {
        var publicKey = new byte[Ed25519.PublicKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.ComputePublicKey(publicKey, AlicePrivateKey));
        publicKey = new byte[Ed25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.ComputePublicKey(publicKey, AlicePrivateKey));
    }
    
    [TestMethod]
    public void ComputePublicKey_InvalidPrivateKey()
    {
        var publicKey = new byte[Ed25519.PublicKeySize];
        var privateKey = new byte[Ed25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.ComputePublicKey(publicKey, privateKey));
        privateKey = new byte[Ed25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.ComputePublicKey(publicKey, privateKey));
    }
    
    [TestMethod]
    public void GetX25519PublicKey_ValidInputs()
    {
        Span<byte> publicKey = stackalloc byte[X25519.PublicKeySize];
        Ed25519.GetX25519PublicKey(publicKey, AlicePublicKey);
        Assert.IsTrue(publicKey.SequenceEqual(X25519PublicKey));
    }
    
    [TestMethod]
    public void GetX25519PublicKey_InvalidX25519PublicKey()
    {
        var publicKey = new byte[X25519.PublicKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GetX25519PublicKey(publicKey, AlicePublicKey));
        publicKey = new byte[X25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GetX25519PublicKey(publicKey, AlicePublicKey));
    }
    
    [TestMethod]
    public void GetX25519PublicKey_InvalidEd25519PublicKey()
    {
        var X25519PublicKey = new byte[X25519.PublicKeySize];
        var Ed25519PublicKey = new byte[Ed25519.PublicKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GetX25519PublicKey(X25519PublicKey, Ed25519PublicKey));
        Ed25519PublicKey = new byte[Ed25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GetX25519PublicKey(X25519PublicKey, Ed25519PublicKey));
    }
    
    [TestMethod]
    public void GetX25519PrivateKey_ValidInputs()
    {
        Span<byte> privateKey = stackalloc byte[X25519.PrivateKeySize];
        Ed25519.GetX25519PrivateKey(privateKey, AlicePrivateKey);
        Assert.IsTrue(privateKey.SequenceEqual(X25519PrivateKey));
    }
    
    [TestMethod]
    public void GetX25519PrivateKey_InvalidX25519PrivateKey()
    {
        var privateKey = new byte[X25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GetX25519PrivateKey(privateKey, AlicePrivateKey));
        privateKey = new byte[X25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GetX25519PrivateKey(privateKey, AlicePrivateKey));
    }
    
    [TestMethod]
    public void GetX25519PrivateKey_InvalidEd25519PrivateKey()
    {
        var X25519PrivateKey = new byte[X25519.PrivateKeySize];
        var Ed25519PrivateKey = new byte[Ed25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GetX25519PrivateKey(X25519PrivateKey, Ed25519PrivateKey));
        Ed25519PrivateKey = new byte[Ed25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GetX25519PrivateKey(X25519PrivateKey, Ed25519PrivateKey));
    }
    
    [TestMethod]
    public void Sign_ValidInputs()
    {
        Span<byte> signature = stackalloc byte[Ed25519.SignatureSize];
        Ed25519.Sign(signature, Message, AlicePrivateKey);
        Assert.IsTrue(signature.SequenceEqual(Signature));
    }
    
    [TestMethod]
    public void Sign_DifferentMessage()
    {
        Span<byte> signature = stackalloc byte[Ed25519.SignatureSize];
        Span<byte> message = Message.ToArray();
        message[0]++;
        Ed25519.Sign(signature, message, AlicePrivateKey);
        Assert.IsFalse(signature.SequenceEqual(Signature));
    }
    
    [TestMethod]
    public void Sign_DifferentPrivateKey()
    {
        Span<byte> signature = stackalloc byte[Ed25519.SignatureSize];
        Ed25519.Sign(signature, Message, EvePrivateKey);
        Assert.IsFalse(signature.SequenceEqual(Signature));
    }

    [TestMethod]
    public void Sign_InvalidSignature()
    {
        var signature = new byte[Ed25519.SignatureSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Sign(signature, Message, AlicePrivateKey));
        signature = new byte[Ed25519.SignatureSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Sign(signature, Message, AlicePrivateKey));
    }
    
    [TestMethod]
    public void Sign_InvalidMessage()
    {
        var signature = new byte[Ed25519.SignatureSize];
        var message = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Sign(signature, message, AlicePrivateKey));
    }
    
    [TestMethod]
    public void Sign_InvalidPrivateKey()
    {
        var signature = new byte[Ed25519.SignatureSize];
        var privateKey = new byte[Ed25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Sign(signature, Message, privateKey));
        privateKey = new byte[Ed25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Sign(signature, Message, privateKey));
    }
    
    [TestMethod]
    public void Verify_ValidInputs()
    {
        bool valid = Ed25519.Verify(Signature, Message, AlicePublicKey);
        Assert.IsTrue(valid);
    }
    
    [TestMethod]
    public void Verify_WrongSignature()
    {
        bool valid = Ed25519.Verify(AlicePrivateKey, Message, AlicePublicKey);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void Verify_WrongMessage()
    {
        bool valid = Ed25519.Verify(Signature, Seed, AlicePublicKey);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void Verify_WrongPublicKey()
    {
        bool valid = Ed25519.Verify(Signature, Message, EvePublicKey);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void Verify_InvalidSignature()
    {
        var signature = new byte[Ed25519.SignatureSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Verify(signature, Message, AlicePublicKey));
        signature = new byte[Ed25519.SignatureSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Verify(signature, Message, AlicePublicKey));
    }
    
    [TestMethod]
    public void Verify_InvalidMessage()
    {
        var signature = new byte[Ed25519.SignatureSize];
        var message = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Verify(signature, message, AlicePublicKey));
    }
    
    [TestMethod]
    public void Verify_InvalidPublicKey()
    {
        var signature = new byte[Ed25519.SignatureSize];
        var publicKey = new byte[Ed25519.PublicKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Verify(signature, Message, publicKey));
        publicKey = new byte[Ed25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Verify(signature, Message, publicKey));
    }
}