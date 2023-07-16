using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class Argon2idTests
{
    // https://github.com/jedisct1/libsodium/blob/master/test/default/pwhash_argon2id.c
    public static IEnumerable<object[]> StringTestVectors()
    {
        yield return new object[]
        {
            true,
            "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        };
        yield return new object[]
        {
            true,
            "$argon2id$v=19$m=4096,t=19,p=1$PkEgMTYtYnl0ZXMgc2FsdA$ltB/ue1kPtBMBGfsysMpPigE6hiNEKZ9vs8vLNVDQGA",
            "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg "
        };
        yield return new object[]
        {
            true,
            "$argon2id$v=19$m=4096,t=1,p=3$PkEgcHJldHR5IGxvbmcgc2FsdA$HUqx5Z1b/ZypnUrvvJ5UC2Q+T6Q1WwASK/Kr9dRbGA0",
            "K3S=KyH#)36_?]LxeR8QNKw6X=gFbxai$C%29V*"
        };
        yield return new object[]
        {
            false,
            "$argon2id$v=19$m=4096,t=0,p=1$X1NhbHQAAAAAAAAAAAAAAA$bWh++MKN1OiFHKgIWTLvIi1iHicmHH7+Fv3K88ifFfI",
            ""
        };
        yield return new object[]
        {
            false,
            "$argon2id$v=19$m=2048,t=4,p=1$SWkxaUhpY21ISDcrRnYzSw$Mbg/Eck1kpZir5T9io7C64cpffdTBaORgyriLQFgQj8",
            ""
        };
        yield return new object[]
        {
            false,
            "$argon2id$v=19$m=4096,t=0,p=1$PkEgMTYtYnl0ZXMgc2FsdA$ltB/ue1kPtBMBGfsysMpPigE6hiNEKZ9vs8vLNVDQGA",
            "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg "
        };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, Argon2id.KeySize);
        Assert.AreEqual(16, Argon2id.MinKeySize);
        Assert.AreEqual(16, Argon2id.SaltSize);
        Assert.AreEqual(1, Argon2id.MinIterations);
        Assert.AreEqual(8192, Argon2id.MinMemorySize);
        Assert.AreEqual(92, Argon2id.MinHashSize);
        Assert.AreEqual(128, Argon2id.MaxHashSize);
        Assert.AreEqual("$argon2id$", Argon2id.HashPrefix);
    }

    [TestMethod]
    [DataRow("9108d194ef44c4a2ca75be1107a931359a99b0c9a41187bf9f2c0cb22ec73318", "correct horse battery staple", "bca21536da522787b9267be10c1b7499", 3, 16777216)]
    public void DeriveKey_Valid(string outputKeyingMaterial, string password, string salt, int iterations, int memorySize)
    {
        Span<byte> okm = stackalloc byte[outputKeyingMaterial.Length / 2];
        Span<byte> p = Encoding.UTF8.GetBytes(password);
        Span<byte> s = Convert.FromHexString(salt);

        Argon2id.DeriveKey(okm, p, s, iterations, memorySize);

        Assert.AreEqual(outputKeyingMaterial, Convert.ToHexString(okm).ToLower());
    }

    [TestMethod]
    [DataRow(Argon2id.MinKeySize - 1, Argon2id.KeySize, Argon2id.SaltSize, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinKeySize, Argon2id.KeySize, Argon2id.SaltSize + 1, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinKeySize, Argon2id.KeySize, Argon2id.SaltSize - 1, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinKeySize, Argon2id.KeySize, Argon2id.SaltSize, Argon2id.MinIterations - 1, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinKeySize, Argon2id.KeySize, Argon2id.SaltSize, Argon2id.MinIterations, Argon2id.MinMemorySize - 1 )]
    public void DeriveKey_Invalid(int outputKeyingMaterialSize, int passwordSize, int saltSize, int iterations, int memorySize)
    {
        var okm = new byte[outputKeyingMaterialSize];
        var p = new byte[passwordSize];
        var s = new byte[saltSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.DeriveKey(okm, p, s, iterations, memorySize));
    }

    [TestMethod]
    [DataRow("correct horse battery staple", 3, 16777216)]
    public void ComputeHash_Valid(string password, int iterations, int memorySize)
    {
        Span<byte> h = stackalloc byte[Argon2id.MaxHashSize];
        Span<byte> p = Encoding.UTF8.GetBytes(password);

        Argon2id.ComputeHash(h, p, iterations, memorySize);

        Assert.IsFalse(h.SequenceEqual(new byte[h.Length]));

        bool valid = Argon2id.VerifyHash(h, p);
        Assert.IsTrue(valid);

        bool rehash = Argon2id.NeedsRehash(h, iterations, memorySize);
        Assert.IsFalse(rehash);
    }

    [TestMethod]
    [DataRow(Argon2id.MaxHashSize + 1, Argon2id.KeySize, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MaxHashSize - 1, Argon2id.KeySize, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MaxHashSize, Argon2id.KeySize, Argon2id.MinIterations - 1, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MaxHashSize, Argon2id.KeySize, Argon2id.MinIterations, Argon2id.MinMemorySize - 1)]
    public void ComputeHash_Invalid(int hashSize, int passwordSize, int iterations, int memorySize)
    {
        var h = new byte[hashSize];
        var p = new byte[passwordSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.ComputeHash(h, p, iterations, memorySize));
    }

    [TestMethod]
    [DynamicData(nameof(StringTestVectors), DynamicDataSourceType.Method)]
    public void VerifyHash_Valid(bool expected, string hash, string password)
    {
        Span<byte> h = Encoding.UTF8.GetBytes(hash);
        Span<byte> p = Encoding.UTF8.GetBytes(password);

        bool valid = Argon2id.VerifyHash(h, p);

        Assert.AreEqual(expected, valid);
    }

    [TestMethod]
    [DataRow(Argon2id.MaxHashSize + 1, Argon2id.KeySize)]
    [DataRow(Argon2id.MinHashSize - 1, Argon2id.KeySize)]
    public void VerifyHash_Invalid(int hashSize, int passwordSize)
    {
        var h = new byte[hashSize];
        var p = new byte[passwordSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.VerifyHash(h, p));
    }

    [TestMethod]
    [DataRow(false, "$argon2id$v=19$m=16384,t=3,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us", 3, 16777216)]
    [DataRow(true, "$argon2id$v=19$m=16384,t=3,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us", 4, 16777216)]
    [DataRow(true, "$argon2id$v=19$m=16384,t=3,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us", 3, 26777216)]
    public void NeedsRehash_Valid(bool expected, string hash, int iterations, int memorySize)
    {
        Span<byte> h = Encoding.UTF8.GetBytes(hash);

        bool rehash = Argon2id.NeedsRehash(h, iterations, memorySize);

        Assert.AreEqual(expected, rehash);
    }

    [TestMethod]
    [DataRow("argon2id$v=19$m=16384,t=3,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us", 3, 16777216)]
    [DataRow("$argon2id$v19$m=16384,t=3,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us", 3, 16777216)]
    [DataRow("$argon2id$v=19$m=16384t=3,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us", 3, 16777216)]
    public void NeedsRehash_Tampered(string hash, int iterations, int memorySize)
    {
        var h = Encoding.UTF8.GetBytes(hash);

        Assert.ThrowsException<FormatException>(() => Argon2id.NeedsRehash(h, iterations, memorySize));
    }

    [TestMethod]
    [DataRow(Argon2id.MaxHashSize + 1, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinHashSize - 1, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinHashSize, Argon2id.MinIterations - 1, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinHashSize, Argon2id.MinIterations, Argon2id.MinMemorySize - 1)]
    public void NeedsRehash_Invalid(int hashSize, int iterations, int memorySize)
    {
        var h = new byte[hashSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Argon2id.NeedsRehash(h, iterations, memorySize));
    }
}
