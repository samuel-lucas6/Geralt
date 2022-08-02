using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class Argon2idTests
{
    // Generated using libsodium-core
    private static readonly byte[] Argon2idKey = Convert.FromHexString("9108d194ef44c4a2ca75be1107a931359a99b0c9a41187bf9f2c0cb22ec73318");
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("correct horse battery staple");
    private static readonly byte[] Salt = Convert.FromHexString("bca21536da522787b9267be10c1b7499");
    private const string Argon2idHash = "$argon2id$v=19$m=16384,t=3,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us";
    private const string WrongArgon2idHash = "$argon2id$v=19$m=16384,t=1,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us";
    // Smallest memory size for testing
    private const int Iterations = 3;
    private const int MemorySize = 16777216;
    
    [TestMethod]
    public void DeriveKey_ValidInputs()
    {
        Span<byte> key = stackalloc byte[Argon2id.KeySize];
        Argon2id.DeriveKey(key, Password, Salt, Iterations, MemorySize);
        Assert.IsTrue(key.SequenceEqual(Argon2idKey));
    }

    [TestMethod]
    public void DeriveKey_InvalidKey()
    {
        var key = new byte[Argon2id.MinKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.DeriveKey(key, Password, Salt, Iterations, MemorySize));
    }

    [TestMethod]
    public void DeriveKey_InvalidPassword()
    {
        var key = new byte[Argon2id.KeySize];
        var password = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.DeriveKey(key, password, Salt, Iterations, MemorySize));
    }

    [TestMethod]
    public void DeriveKey_InvalidSalt()
    {
        var key = new byte[Argon2id.KeySize];
        var salt = new byte[Argon2id.SaltSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.DeriveKey(key, Password, salt, Iterations, MemorySize));
        salt = new byte[Argon2id.SaltSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.DeriveKey(key, Password, salt, Iterations, MemorySize));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidIterations()
    {
        var key = new byte[Argon2id.KeySize];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.DeriveKey(key, Password, Salt, Argon2id.MinIterations - 1, MemorySize));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidMemorySize()
    {
        var key = new byte[Argon2id.KeySize];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.DeriveKey(key, Password, Salt, Iterations, Argon2id.MinMemorySize - 1));
    }

    [TestMethod]
    public void ComputeHash_ValidInputs()
    {
        Span<byte> hash = stackalloc byte[Argon2id.MaxHashSize];
        Argon2id.ComputeHash(hash, Password, Iterations, MemorySize);
        bool valid = Argon2id.VerifyHash(hash, Password);
        Assert.IsTrue(valid);
        bool rehash = Argon2id.NeedsRehash(hash, Iterations, MemorySize);
        Assert.IsFalse(rehash);
    }

    [TestMethod]
    public void ComputeHash_InvalidHash()
    {
        var hash = new byte[Argon2id.MaxHashSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.ComputeHash(hash, Password, Iterations, MemorySize));
        hash = new byte[Argon2id.MaxHashSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.ComputeHash(hash, Password, Iterations, MemorySize));
    }
    
    [TestMethod]
    public void ComputeHash_InvalidPassword()
    {
        var hash = new byte[Argon2id.MaxHashSize];
        var password = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.ComputeHash(hash, password, Iterations, MemorySize));
    }

    [TestMethod]
    public void ComputeHash_InvalidIterations()
    {
        var hash = new byte[Argon2id.MaxHashSize];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.ComputeHash(hash, Password, Argon2id.MinIterations - 1, MemorySize));
    }

    [TestMethod]
    public void ComputeHash_InvalidMemorySize()
    {
        var hash = new byte[Argon2id.MaxHashSize];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.ComputeHash(hash, Password, Iterations, Argon2id.MinMemorySize - 1));
    }

    [TestMethod]
    public void VerifyHash_ValidInputs()
    {
        Span<byte> hash = Encoding.UTF8.GetBytes(Argon2idHash);
        bool valid = Argon2id.VerifyHash(hash, Password);
        Assert.IsTrue(valid);
    }

    [TestMethod]
    public void VerifyHash_WrongHash()
    {
        Span<byte> hash = Encoding.UTF8.GetBytes(WrongArgon2idHash);
        bool valid = Argon2id.VerifyHash(hash, Password);
        Assert.IsFalse(valid);
    }

    [TestMethod]
    public void VerifyHash_InvalidHash()
    {
        var hash = new byte[Argon2id.HashPrefix.Length - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.VerifyHash(hash, Password));
        hash = new byte[Argon2id.MaxHashSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.VerifyHash(hash, Password));
    }

    [TestMethod]
    public void VerifyHash_InvalidPassword()
    {
        var hash = Encoding.UTF8.GetBytes(Argon2idHash);
        var password = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.VerifyHash(hash, password));
    }

    [TestMethod]
    public void NeedsRehash_CorrectParameters()
    {
        Span<byte> hash = Encoding.UTF8.GetBytes(Argon2idHash);
        bool rehash = Argon2id.NeedsRehash(hash, Iterations, MemorySize);
        Assert.IsFalse(rehash);
    }

    [TestMethod]
    public void NeedsRehash_WrongIterations()
    {
        Span<byte> hash = Encoding.UTF8.GetBytes(Argon2idHash);
        bool rehash = Argon2id.NeedsRehash(hash, Iterations + 1, MemorySize);
        Assert.IsTrue(rehash);
    }

    [TestMethod]
    public void NeedsRehash_WrongMemorySize()
    {
        Span<byte> hash = Encoding.UTF8.GetBytes(Argon2idHash);
        bool rehash = Argon2id.NeedsRehash(hash, Iterations, MemorySize * 2);
        Assert.IsTrue(rehash);
    }

    [TestMethod]
    public void NeedsRehash_InvalidHash()
    {
        var hash = new byte[Argon2id.HashPrefix.Length - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.NeedsRehash(hash, Iterations, MemorySize));
        hash = new byte[Argon2id.MaxHashSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.NeedsRehash(hash, Iterations, MemorySize));
    }
    
    [TestMethod]
    public void NeedsRehash_CorruptHash()
    {
        var hash = Encoding.UTF8.GetBytes(Argon2idHash.Trim('$'));
        Assert.ThrowsException<FormatException>(() => Argon2id.NeedsRehash(hash, Iterations, MemorySize));
    }
    
    [TestMethod]
    public void NeedsRehash_InvalidIterations()
    {
        var hash = Encoding.UTF8.GetBytes(Argon2idHash);
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.NeedsRehash(hash, Argon2id.MinIterations - 1, MemorySize));
    }
    
    [TestMethod]
    public void NeedsRehash_InvalidMemorySize()
    {
        var hash = Encoding.UTF8.GetBytes(Argon2idHash);
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.NeedsRehash(hash, Iterations, Argon2id.MinMemorySize - 1));
    }
}