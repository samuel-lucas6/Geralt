using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class X25519Tests
{
    /// RFC 7748 Section 6.1: https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
    private static readonly byte[] AlicePrivateKey = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    private static readonly byte[] AlicePublicKey = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    private static readonly byte[] BobPrivateKey = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    private static readonly byte[] BobPublicKey = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    private static readonly byte[] SharedSecret = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    // Generated using libsodium-core
    private static readonly byte[] Seed = Convert.FromHexString("b589764bb6395e13788436f93f4eaa4c858900b6a12328e8626ded5b39d2c7e9");
    private static readonly byte[] SharedKey = Convert.FromHexString("519fb3af2f3f9e310718cf1f8bdec6e26ab64affe730f0f8b43c43b0e8ee52be");
    private static readonly byte[] PreSharedKey = Convert.FromHexString("5dbbfd1c5549181aa9319cd71b946757e1f4769aee9568bd360b651a86ea29a2");
    private static readonly byte[] SharedKeyWithPreSharedKey = Convert.FromHexString("a91209efc719601f61c54f74d369fe14f997a29a91b174d5771614b6c9407ad1");
    private static readonly byte[] EvePrivateKey = Convert.FromHexString("452e18802da843e0da527dc3f184a1d04aec69d67e53addd2fc3f8f5cb031a8b");
    private static readonly byte[] EvePublicKey = Convert.FromHexString("a0a219524fe1f1d496c2642c76c3ca6510e8d2620c1a325f1fdea02c59f25861");
    
    [TestMethod]
    public void GenerateKeyPair_ValidInputs()
    {
        Span<byte> publicKey = stackalloc byte[X25519.PublicKeySize];
        Span<byte> privateKey = stackalloc byte[X25519.PrivateKeySize];
        X25519.GenerateKeyPair(publicKey, privateKey);
        Assert.IsFalse(publicKey.SequenceEqual(new byte[publicKey.Length]));
        Assert.IsFalse(privateKey.SequenceEqual(new byte[privateKey.Length]));
    }
    
    [TestMethod]
    public void GenerateKeyPair_InvalidPublicKey()
    {
        var publicKey = new byte[X25519.PublicKeySize - 1];
        var privateKey = new byte[X25519.PrivateKeySize];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(publicKey, privateKey));
        publicKey = new byte[X25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(publicKey, privateKey));
    }
    
    [TestMethod]
    public void GenerateKeyPair_InvalidPrivateKey()
    {
        var publicKey = new byte[X25519.PublicKeySize];
        var privateKey = new byte[X25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(publicKey, privateKey));
        privateKey = new byte[X25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(publicKey, privateKey));
    }
    
    [TestMethod]
    public void GenerateSeededKeyPair_ValidInputs()
    {
        Span<byte> publicKey = stackalloc byte[X25519.PublicKeySize];
        Span<byte> privateKey = stackalloc byte[X25519.PrivateKeySize];
        X25519.GenerateKeyPair(publicKey, privateKey, Seed);
        Assert.IsFalse(publicKey.SequenceEqual(new byte[publicKey.Length]));
        Assert.IsFalse(privateKey.SequenceEqual(new byte[privateKey.Length]));
    }
    
    [TestMethod]
    public void GenerateSeededKeyPair_InvalidPublicKey()
    {
        var publicKey = new byte[X25519.PublicKeySize - 1];
        var privateKey = new byte[X25519.PrivateKeySize];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(publicKey, privateKey, Seed));
        publicKey = new byte[X25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(publicKey, privateKey, Seed));
    }
    
    [TestMethod]
    public void GenerateSeededKeyPair_InvalidPrivateKey()
    {
        var publicKey = new byte[X25519.PublicKeySize];
        var privateKey = new byte[X25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(publicKey, privateKey, Seed));
        privateKey = new byte[X25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(publicKey, privateKey, Seed));
    }
    
    [TestMethod]
    public void GenerateSeededKeyPair_InvalidSeed()
    {
        var publicKey = new byte[X25519.PublicKeySize];
        var privateKey = new byte[X25519.PrivateKeySize];
        var seed = new byte[X25519.SeedSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(publicKey, privateKey, seed));
        seed = new byte[X25519.SeedSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(publicKey, privateKey, seed));
    }
    
    [TestMethod]
    public void ComputePublicKey_ValidInputs()
    {
        Span<byte> publicKey = stackalloc byte[X25519.PublicKeySize];
        X25519.ComputePublicKey(publicKey, AlicePrivateKey);
        Assert.IsTrue(publicKey.SequenceEqual(AlicePublicKey));
    }
    
    [TestMethod]
    public void ComputePublicKey_DifferentPrivateKey()
    {
        Span<byte> publicKey = stackalloc byte[X25519.PublicKeySize];
        X25519.ComputePublicKey(publicKey, BobPrivateKey);
        Assert.IsFalse(publicKey.SequenceEqual(AlicePublicKey));
    }
    
    [TestMethod]
    public void ComputePublicKey_InvalidPublicKey()
    {
        var publicKey = new byte[X25519.PublicKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.ComputePublicKey(publicKey, AlicePrivateKey));
        publicKey = new byte[X25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.ComputePublicKey(publicKey, AlicePrivateKey));
    }
    
    [TestMethod]
    public void ComputePublicKey_InvalidPrivateKey()
    {
        var publicKey = new byte[X25519.PublicKeySize];
        var privateKey = new byte[X25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.ComputePublicKey(publicKey, privateKey));
        privateKey = new byte[X25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.ComputePublicKey(publicKey, privateKey));
    }
    
    [TestMethod]
    public void ComputeSharedSecret_ValidInputs()
    {
        Span<byte> aliceSharedSecret = stackalloc byte[X25519.SharedSecretSize];
        X25519.ComputeSharedSecret(aliceSharedSecret, AlicePrivateKey, BobPublicKey);
        Assert.IsTrue(aliceSharedSecret.SequenceEqual(SharedSecret));
        Span<byte> bobSharedSecret = stackalloc byte[X25519.SharedSecretSize];
        X25519.ComputeSharedSecret(bobSharedSecret, BobPrivateKey, AlicePublicKey);
        Assert.IsTrue(bobSharedSecret.SequenceEqual(aliceSharedSecret));
    }
    
    [TestMethod]
    public void ComputeSharedSecret_WeakPublicKey()
    {
        var sharedSecret = new byte[X25519.SharedSecretSize];
        var publicKey = new byte[X25519.PublicKeySize];
        Assert.ThrowsException<CryptographicException>(() => X25519.ComputeSharedSecret(sharedSecret, AlicePrivateKey, publicKey));
    }
    
    [TestMethod]
    public void ComputeSharedSecret_InvalidPublicKey()
    {
        var sharedSecret = new byte[X25519.SharedSecretSize];
        var publicKey = new byte[X25519.PublicKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.ComputeSharedSecret(sharedSecret, AlicePrivateKey, publicKey));
        publicKey = new byte[X25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.ComputeSharedSecret(sharedSecret, AlicePrivateKey, publicKey));
    }
    
    [TestMethod]
    public void ComputeSharedSecret_InvalidPrivateKey()
    {
        var sharedSecret = new byte[X25519.SharedSecretSize];
        var privateKey = new byte[X25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.ComputeSharedSecret(sharedSecret, privateKey, BobPublicKey));
        privateKey = new byte[X25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.ComputeSharedSecret(sharedSecret, privateKey, BobPublicKey));
    }
    
    [TestMethod]
    public void DeriveSharedKey_ValidInputs()
    {
        Span<byte> aliceSharedKey = stackalloc byte[X25519.SharedKeySize];
        X25519.DeriveSenderSharedKey(aliceSharedKey, AlicePrivateKey, BobPublicKey);
        Assert.IsTrue(aliceSharedKey.SequenceEqual(SharedKey));
        Span<byte> bobSharedKey = stackalloc byte[X25519.SharedKeySize];
        X25519.DeriveRecipientSharedKey(bobSharedKey, BobPrivateKey, AlicePublicKey);
        Assert.IsTrue(bobSharedKey.SequenceEqual(aliceSharedKey));
    }
    
    [TestMethod]
    public void DeriveSharedKeyWithPreSharedKey_ValidInputs()
    {
        Span<byte> aliceSharedKey = stackalloc byte[X25519.SharedKeySize];
        X25519.DeriveSenderSharedKey(aliceSharedKey, AlicePrivateKey, BobPublicKey, PreSharedKey);
        Assert.IsTrue(aliceSharedKey.SequenceEqual(SharedKeyWithPreSharedKey));
        Span<byte> bobSharedKey = stackalloc byte[X25519.SharedKeySize];
        X25519.DeriveRecipientSharedKey(bobSharedKey, BobPrivateKey, AlicePublicKey, PreSharedKey);
        Assert.IsTrue(bobSharedKey.SequenceEqual(aliceSharedKey));
    }
    
    [TestMethod]
    public void DeriveSharedKey_DifferentPrivateKeys()
    {
        Span<byte> aliceSharedKey = stackalloc byte[X25519.SharedKeySize];
        X25519.DeriveSenderSharedKey(aliceSharedKey, AlicePrivateKey, BobPublicKey);
        Span<byte> eveSharedKey = stackalloc byte[X25519.SharedKeySize];
        X25519.DeriveRecipientSharedKey(eveSharedKey, EvePrivateKey, AlicePublicKey);
        Assert.IsFalse(eveSharedKey.SequenceEqual(aliceSharedKey));
    }
    
    [TestMethod]
    public void DeriveSharedKey_DifferentPublicKeys()
    {
        Span<byte> aliceSharedKey = stackalloc byte[X25519.SharedKeySize];
        X25519.DeriveSenderSharedKey(aliceSharedKey, AlicePrivateKey, BobPublicKey);
        Span<byte> bobSharedKey = stackalloc byte[X25519.SharedKeySize];
        X25519.DeriveRecipientSharedKey(bobSharedKey, BobPrivateKey, EvePublicKey);
        Assert.IsFalse(bobSharedKey.SequenceEqual(aliceSharedKey));
    }
    
    [TestMethod]
    public void DeriveSharedKey_DifferentPreSharedKey()
    {
        Span<byte> aliceSharedKey = stackalloc byte[X25519.SharedKeySize];
        X25519.DeriveSenderSharedKey(aliceSharedKey, AlicePrivateKey, BobPublicKey, PreSharedKey);
        Span<byte> bobSharedKey = stackalloc byte[X25519.SharedKeySize];
        X25519.DeriveRecipientSharedKey(bobSharedKey, BobPrivateKey, AlicePublicKey, SharedSecret);
        Assert.IsFalse(bobSharedKey.SequenceEqual(aliceSharedKey));
    }
    
    [TestMethod]
    public void DeriveSharedKey_InvalidSharedKey()
    {
        var sharedKey = new byte[X25519.SharedKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveSenderSharedKey(sharedKey, AlicePrivateKey, BobPublicKey));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveRecipientSharedKey(sharedKey, BobPrivateKey, AlicePublicKey));
        sharedKey = new byte[X25519.SharedKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveSenderSharedKey(sharedKey, AlicePrivateKey, BobPublicKey));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveRecipientSharedKey(sharedKey, BobPrivateKey, AlicePublicKey));
    }
    
    [TestMethod]
    public void DeriveSharedKey_InvalidPublicKey()
    {
        var sharedKey = new byte[X25519.SharedKeySize];
        var publicKey = new byte[X25519.PublicKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveSenderSharedKey(sharedKey, AlicePrivateKey, publicKey));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveRecipientSharedKey(sharedKey, BobPrivateKey, publicKey));
        publicKey = new byte[X25519.PublicKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveSenderSharedKey(sharedKey, AlicePrivateKey, publicKey));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveRecipientSharedKey(sharedKey, BobPrivateKey, publicKey));
    }
    
    [TestMethod]
    public void DeriveSharedKey_WeakPublicKey()
    {
        var sharedKey = new byte[X25519.SharedKeySize];
        var publicKey = new byte[X25519.PublicKeySize];
        Assert.ThrowsException<CryptographicException>(() => X25519.DeriveSenderSharedKey(sharedKey, AlicePrivateKey, publicKey));
        Assert.ThrowsException<CryptographicException>(() => X25519.DeriveRecipientSharedKey(sharedKey, BobPrivateKey, publicKey));
    }
    
    [TestMethod]
    public void DeriveSharedKey_InvalidPrivateKey()
    {
        var sharedKey = new byte[X25519.SharedKeySize];
        var privateKey = new byte[X25519.PrivateKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveSenderSharedKey(sharedKey, privateKey, BobPublicKey));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveRecipientSharedKey(sharedKey, privateKey, AlicePublicKey));
        privateKey = new byte[X25519.PrivateKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveSenderSharedKey(sharedKey, privateKey, BobPublicKey));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveRecipientSharedKey(sharedKey, privateKey, AlicePublicKey));
    }
    
    [TestMethod]
    public void DeriveSharedKey_InvalidPreSharedKey()
    {
        var sharedKey = new byte[X25519.SharedKeySize];
        var preSharedKey = new byte[X25519.MinPreSharedKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveSenderSharedKey(sharedKey, AlicePrivateKey, BobPublicKey, preSharedKey));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveRecipientSharedKey(sharedKey, BobPrivateKey, AlicePublicKey, preSharedKey));
        preSharedKey = new byte[X25519.MaxPreSharedKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveSenderSharedKey(sharedKey, AlicePrivateKey, BobPublicKey, preSharedKey));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveRecipientSharedKey(sharedKey, BobPrivateKey, AlicePublicKey, preSharedKey));
    }
}