namespace Geralt.Tests;

[TestClass]
public class IncrementalBLAKE2bTests
{
    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, IncrementalBLAKE2b.HashSize);
        Assert.AreEqual(32, IncrementalBLAKE2b.KeySize);
        Assert.AreEqual(32, IncrementalBLAKE2b.TagSize);
        Assert.AreEqual(128, IncrementalBLAKE2b.BlockSize);
        Assert.AreEqual(16, IncrementalBLAKE2b.MinHashSize);
        Assert.AreEqual(64, IncrementalBLAKE2b.MaxHashSize);
        Assert.AreEqual(16, IncrementalBLAKE2b.MinTagSize);
        Assert.AreEqual(64, IncrementalBLAKE2b.MaxTagSize);
        Assert.AreEqual(16, IncrementalBLAKE2b.MinKeySize);
        Assert.AreEqual(64, IncrementalBLAKE2b.MaxKeySize);
    }

    [TestMethod]
    [DynamicData(nameof(BLAKE2bTests.UnkeyedTestVectors), typeof(BLAKE2bTests))]
    [DynamicData(nameof(BLAKE2bTests.KeyedTestVectors), typeof(BLAKE2bTests))]
    public void Compute_Valid(string hash, string message, string? key = null)
    {
        Span<byte> h = stackalloc byte[hash.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = key != null ? Convert.FromHexString(key) : Span<byte>.Empty;

        using var blake2b = new IncrementalBLAKE2b(h.Length, k);
        if (m.Length > 1) {
            blake2b.Update(m[..(m.Length / 2)]);
            blake2b.Update(m[(m.Length / 2)..]);
        }
        else {
            blake2b.Update(m);
        }
        blake2b.Finalize(h);

        Assert.AreEqual(hash, Convert.ToHexString(h).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(BLAKE2bTests.UnkeyedTestVectors), typeof(BLAKE2bTests))]
    [DynamicData(nameof(BLAKE2bTests.KeyedTestVectors), typeof(BLAKE2bTests))]
    public void Reinitialize_Valid(string hash, string message, string? key = null)
    {
        Span<byte> h = stackalloc byte[hash.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = key != null ? Convert.FromHexString(key) : Span<byte>.Empty;

        using var blake2b = new IncrementalBLAKE2b(h.Length, k);
        blake2b.Update(m);
        blake2b.Finalize(h);
        blake2b.Reinitialize(h.Length, k);
        blake2b.Update(m);
        bool valid = blake2b.FinalizeAndVerify(h);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(BLAKE2bTests.UnkeyedTestVectors), typeof(BLAKE2bTests))]
    [DynamicData(nameof(BLAKE2bTests.KeyedTestVectors), typeof(BLAKE2bTests))]
    public void CacheState_Valid(string hash, string message, string? key = null)
    {
        Span<byte> h = stackalloc byte[hash.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = key != null ? Convert.FromHexString(key) : Span<byte>.Empty;

        using var blake2b = new IncrementalBLAKE2b(h.Length, k);
        blake2b.CacheState();
        blake2b.Update(m);
        blake2b.Finalize(h);
        h.Clear();
        blake2b.RestoreCachedState();
        blake2b.Update(m);
        blake2b.CacheState();
        blake2b.Finalize(h);
        h.Clear();
        blake2b.RestoreCachedState();
        blake2b.Finalize(h);

        Assert.AreEqual(hash, Convert.ToHexString(h).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(BLAKE2bTests.KeyedTestVectors), typeof(BLAKE2bTests))]
    public void Verify_Valid(string hash, string message, string key)
    {
        Span<byte> h = Convert.FromHexString(hash);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        using var blake2b = new IncrementalBLAKE2b(h.Length, k);
        if (m.Length > 1) {
            blake2b.Update(m[..(m.Length / 2)]);
            blake2b.Update(m[(m.Length / 2)..]);
        }
        else {
            blake2b.Update(m);
        }
        bool valid = blake2b.FinalizeAndVerify(h);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(BLAKE2bTests.KeyedTestVectors), typeof(BLAKE2bTests))]
    public void Verify_Tampered(string hash, string message, string key)
    {
        var parameters = new Dictionary<string, byte[]>
        {
            { "h", Convert.FromHexString(hash) },
            { "m", Convert.FromHexString(message) },
            { "k", Convert.FromHexString(key) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            using var blake2b = new IncrementalBLAKE2b(parameters["h"].Length, parameters["k"]);
            blake2b.Update(parameters["m"]);
            bool valid = blake2b.FinalizeAndVerify(parameters["h"]);
            param[0]--;
            Assert.IsFalse(valid);
        }
    }

    [TestMethod]
    [DynamicData(nameof(BLAKE2bTests.TagInvalidParameterSizes), typeof(BLAKE2bTests))]
    public void Incremental_Invalid(int hashSize, int messageSize, int keySize)
    {
        var h = new byte[hashSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        if (keySize is < IncrementalBLAKE2b.MinKeySize or > IncrementalBLAKE2b.MaxKeySize) {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new IncrementalBLAKE2b(hashSize, k));
        }
        else if (hashSize is < IncrementalBLAKE2b.MinHashSize or > IncrementalBLAKE2b.MaxHashSize) {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new IncrementalBLAKE2b(hashSize));
            using var blake2b = new IncrementalBLAKE2b(IncrementalBLAKE2b.MaxHashSize);
            blake2b.Update(m);
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => blake2b.Finalize(h));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => blake2b.FinalizeAndVerify(h));
        }
    }

    [TestMethod]
    [DynamicData(nameof(BLAKE2bTests.UnkeyedTestVectors), typeof(BLAKE2bTests))]
    [DynamicData(nameof(BLAKE2bTests.KeyedTestVectors), typeof(BLAKE2bTests))]
    public void Incremental_InvalidOperation(string hash, string message, string? key = null)
    {
        var h = new byte[hash.Length / 2];
        var m = Convert.FromHexString(message);
        var k = key != null ? Convert.FromHexString(key) : Array.Empty<byte>();

        using var blake2b = new IncrementalBLAKE2b(h.Length, k);
        blake2b.Update(m);
        blake2b.Finalize(h);

        Assert.ThrowsExactly<InvalidOperationException>(() => blake2b.Update(m));
        Assert.ThrowsExactly<InvalidOperationException>(() => blake2b.Finalize(h));
        Assert.ThrowsExactly<InvalidOperationException>(() => blake2b.FinalizeAndVerify(h));
        Assert.ThrowsExactly<InvalidOperationException>(() => blake2b.CacheState());
        Assert.ThrowsExactly<InvalidOperationException>(() => blake2b.RestoreCachedState());

        blake2b.Reinitialize(h.Length, k);
        blake2b.Update(m);
        blake2b.FinalizeAndVerify(h);

        Assert.ThrowsExactly<InvalidOperationException>(() => blake2b.Update(m));
        Assert.ThrowsExactly<InvalidOperationException>(() => blake2b.Finalize(h));
        Assert.ThrowsExactly<InvalidOperationException>(() => blake2b.FinalizeAndVerify(h));
        Assert.ThrowsExactly<InvalidOperationException>(() => blake2b.CacheState());
        Assert.ThrowsExactly<InvalidOperationException>(() => blake2b.RestoreCachedState());
    }

    [TestMethod]
    [DynamicData(nameof(BLAKE2bTests.UnkeyedTestVectors), typeof(BLAKE2bTests))]
    [DynamicData(nameof(BLAKE2bTests.KeyedTestVectors), typeof(BLAKE2bTests))]
    public void Incremental_Disposed(string hash, string message, string? key = null)
    {
        var h = new byte[hash.Length / 2];
        var m = Convert.FromHexString(message);
        var k = key != null ? Convert.FromHexString(key) : Array.Empty<byte>();

        var blake2b = new IncrementalBLAKE2b(h.Length, k);
        blake2b.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => blake2b.Reinitialize(h.Length, k));
        Assert.ThrowsExactly<ObjectDisposedException>(() => blake2b.Update(m));
        Assert.ThrowsExactly<ObjectDisposedException>(() => blake2b.Finalize(h));
        Assert.ThrowsExactly<ObjectDisposedException>(() => blake2b.FinalizeAndVerify(h));
        Assert.ThrowsExactly<ObjectDisposedException>(() => blake2b.CacheState());
        Assert.ThrowsExactly<ObjectDisposedException>(() => blake2b.RestoreCachedState());
        blake2b.Dispose();
    }
}
