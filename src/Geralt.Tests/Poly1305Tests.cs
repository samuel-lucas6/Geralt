using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class Poly1305Tests
{
    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.5.2
    public static IEnumerable<object[]> Rfc8439TestVectors()
    {
        yield return new object[]
        {
            "a8061dc1305136c6c22b8baf0c0127a9",
            "43727970746f6772617068696320466f72756d2052657365617263682047726f7570",
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { Poly1305.TagSize + 1, 34, Poly1305.KeySize };
        yield return new object[] { Poly1305.TagSize - 1, 34, Poly1305.KeySize };
        yield return new object[] { Poly1305.TagSize, 34, Poly1305.KeySize + 1 };
        yield return new object[] { Poly1305.TagSize, 34, Poly1305.KeySize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, Poly1305.KeySize);
        Assert.AreEqual(16, Poly1305.TagSize);
    }

    [TestMethod]
    public void IncrementalConstants_Valid()
    {
        Assert.AreEqual(32, IncrementalPoly1305.KeySize);
        Assert.AreEqual(16, IncrementalPoly1305.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439TestVectors), DynamicDataSourceType.Method)]
    public void ComputeTag_Valid(string tag, string message, string oneTimeKey)
    {
        Span<byte> t = stackalloc byte[Poly1305.TagSize];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(oneTimeKey);

        Poly1305.ComputeTag(t, m, k);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.ComputeTag(t, m, k));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439TestVectors), DynamicDataSourceType.Method)]
    public void VerifyTag_Valid(string tag, string message, string oneTimeKey)
    {
        Span<byte> t = Convert.FromHexString(tag);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(oneTimeKey);

        bool valid = Poly1305.VerifyTag(t, m, k);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439TestVectors), DynamicDataSourceType.Method)]
    public void VerifyTag_Tampered(string tag, string message, string oneTimeKey)
    {
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(tag),
            Convert.FromHexString(message),
            Convert.FromHexString(oneTimeKey)
        };

        foreach (var param in parameters) {
            param[0]++;
            bool valid = Poly1305.VerifyTag(parameters[0], parameters[1], parameters[2]);
            param[0]--;
            Assert.IsFalse(valid);
        }
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void VerifyTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.VerifyTag(t, m, k));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439TestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Valid(string tag, string message, string oneTimeKey)
    {
        Span<byte> t = stackalloc byte[Poly1305.TagSize];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(oneTimeKey);

        using var poly1305 = new IncrementalPoly1305(k);
        if (m.Length > 1) {
            poly1305.Update(m[..(m.Length / 2)]);
            poly1305.Update(m[(m.Length / 2)..]);
        }
        else {
            poly1305.Update(m);
        }
        poly1305.Finalize(t);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Incremental_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        if (keySize != IncrementalPoly1305.KeySize) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new IncrementalPoly1305(k));
        }
        else if (tagSize != IncrementalPoly1305.TagSize) {
            using var poly1305 = new IncrementalPoly1305(k);
            poly1305.Update(m);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => poly1305.Finalize(t));
        }
    }
}
