namespace Geralt.Tests;

[TestClass]
public class IncrementalPoly1305Tests
{
    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, IncrementalPoly1305.KeySize);
        Assert.AreEqual(16, IncrementalPoly1305.TagSize);
        Assert.AreEqual(16, IncrementalPoly1305.BlockSize);
    }

    [TestMethod]
    [DynamicData(nameof(Poly1305Tests.Rfc8439TestVectors), typeof(Poly1305Tests))]
    public void Compute_Valid(string tag, string message, string oneTimeKey)
    {
        Span<byte> t = stackalloc byte[Poly1305.TagSize];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(oneTimeKey);

        using var poly1305 = new IncrementalPoly1305(k);
        if (m.Length > Poly1305.BlockSize && m.Length % 2 == 0) {
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
    [DynamicData(nameof(Poly1305Tests.Rfc8439TestVectors), typeof(Poly1305Tests))]
    public void Reinitialize_Valid(string tag, string message, string oneTimeKey)
    {
        Span<byte> t = stackalloc byte[Poly1305.TagSize];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(oneTimeKey);

        using var poly1305 = new IncrementalPoly1305(k);
        poly1305.Update(m);
        poly1305.Finalize(t);
        poly1305.Reinitialize(k);
        poly1305.Update(m);
        bool valid = poly1305.FinalizeAndVerify(t);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(Poly1305Tests.Rfc8439TestVectors), typeof(Poly1305Tests))]
    public void Verify_Valid(string tag, string message, string oneTimeKey)
    {
        Span<byte> t = Convert.FromHexString(tag);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(oneTimeKey);

        using var poly1305 = new IncrementalPoly1305(k);
        if (m.Length > Poly1305.BlockSize && m.Length % 2 == 0) {
            poly1305.Update(m[..(m.Length / 2)]);
            poly1305.Update(m[(m.Length / 2)..]);
        }
        else {
            poly1305.Update(m);
        }
        bool valid = poly1305.FinalizeAndVerify(t);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(Poly1305Tests.Rfc8439TestVectors), typeof(Poly1305Tests))]
    public void Verify_Tampered(string tag, string message, string oneTimeKey)
    {
        var parameters = new Dictionary<string, byte[]>
        {
            { "t", Convert.FromHexString(tag) },
            { "m", Convert.FromHexString(message) },
            { "k", Convert.FromHexString(oneTimeKey) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            using var poly1305 = new IncrementalPoly1305(parameters["k"]);
            poly1305.Update(parameters["m"]);
            bool valid = poly1305.FinalizeAndVerify(parameters["t"]);
            Assert.IsFalse(valid);
            param[0]--;
        }
    }

    [TestMethod]
    [DynamicData(nameof(Poly1305Tests.InvalidParameterSizes), typeof(Poly1305Tests))]
    public void Incremental_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        if (keySize != IncrementalPoly1305.KeySize) {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new IncrementalPoly1305(k));
        }
        else if (tagSize != IncrementalPoly1305.TagSize) {
            using var poly1305 = new IncrementalPoly1305(k);
            poly1305.Update(m);
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => poly1305.Finalize(t));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => poly1305.FinalizeAndVerify(t));
        }
    }

    [TestMethod]
    [DynamicData(nameof(Poly1305Tests.Rfc8439TestVectors), typeof(Poly1305Tests))]
    public void Incremental_InvalidOperation(string tag, string message, string oneTimeKey)
    {
        var t = new byte[Poly1305.TagSize];
        var m = Convert.FromHexString(message);
        var k = Convert.FromHexString(oneTimeKey);

        using var poly1305 = new IncrementalPoly1305(k);
        poly1305.Update(m);
        poly1305.Finalize(t);

        Assert.ThrowsExactly<InvalidOperationException>(() => poly1305.Update(m));
        Assert.ThrowsExactly<InvalidOperationException>(() => poly1305.Finalize(t));
        Assert.ThrowsExactly<InvalidOperationException>(() => poly1305.FinalizeAndVerify(t));

        poly1305.Reinitialize(k);
        poly1305.Update(m);
        poly1305.FinalizeAndVerify(t);

        Assert.ThrowsExactly<InvalidOperationException>(() => poly1305.Update(m));
        Assert.ThrowsExactly<InvalidOperationException>(() => poly1305.Finalize(t));
        Assert.ThrowsExactly<InvalidOperationException>(() => poly1305.FinalizeAndVerify(t));
    }

    [TestMethod]
    [DynamicData(nameof(Poly1305Tests.Rfc8439TestVectors), typeof(Poly1305Tests))]
    public void Incremental_Disposed(string tag, string message, string oneTimeKey)
    {
        var t = Convert.FromHexString(tag);
        var m = Convert.FromHexString(message);
        var k = Convert.FromHexString(oneTimeKey);

        var poly1305 = new IncrementalPoly1305(k);
        poly1305.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => poly1305.Reinitialize(k));
        Assert.ThrowsExactly<ObjectDisposedException>(() => poly1305.Update(m));
        Assert.ThrowsExactly<ObjectDisposedException>(() => poly1305.Finalize(t));
        Assert.ThrowsExactly<ObjectDisposedException>(() => poly1305.FinalizeAndVerify(t));
        poly1305.Dispose();
    }
}
