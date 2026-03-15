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
        Assert.AreEqual(16, IncrementalBLAKE2b.SaltSize);
        Assert.AreEqual(16, IncrementalBLAKE2b.PersonalizationSize);
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
        blake2b.Update(m[..(m.Length / 2)]);
        blake2b.Update(m[(m.Length / 2)..]);
        blake2b.Finalize(h);

        Assert.AreEqual(hash, Convert.ToHexString(h).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(BLAKE2bTests.KeyDerivationTestVectors), typeof(BLAKE2bTests))]
    // Empty personalization (should be equivalent to all-zero)
    [DataRow("10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "", "00000000000000000000000000000000", "")]
    // BLAKE2bTests.UnkeyedTestVectors - BLAKE2 parameter block (containing salt/personalization) is XORed with the IV, meaning all-zero does nothing (no length encoding is performed)
    [DataRow("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", "", "", "", "")]
    [DataRow("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", "", "00000000000000000000000000000000", "00000000000000000000000000000000", "")]
    [DataRow("cbaa0ba7d482b1f301109ae41051991a3289bc1198005af226c5e4f103b66579f461361044c8ba3439ff12c515fb29c52161b7eb9c2837b76a5dc33f7cb2e2e8", "", "", "", "0001020304")]
    [DataRow("cbaa0ba7d482b1f301109ae41051991a3289bc1198005af226c5e4f103b66579f461361044c8ba3439ff12c515fb29c52161b7eb9c2837b76a5dc33f7cb2e2e8", "", "00000000000000000000000000000000", "00000000000000000000000000000000", "0001020304")]
    public void Compute_Salted_Valid(string hash, string key, string personalization, string salt, string message)
    {
        Span<byte> h = stackalloc byte[hash.Length / 2];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(personalization);
        Span<byte> s = Convert.FromHexString(salt);
        Span<byte> m = Convert.FromHexString(message);

        using var blake2b = new IncrementalBLAKE2b(h.Length, k, p, s);
        blake2b.Update(m[..(m.Length / 2)]);
        blake2b.Update(m[(m.Length / 2)..]);
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
        blake2b.Update(m[..(m.Length / 2)]);
        blake2b.Update(m[(m.Length / 2)..]);
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
    [DynamicData(nameof(BLAKE2bTests.SaltedInvalidParameterSizes), typeof(BLAKE2bTests))]
    public void Incremental_Salted_Invalid(int hashSize, int messageSize, int personalizationSize, int saltSize)
    {
        var p = new byte[personalizationSize];
        var s = new byte[saltSize];

        if (personalizationSize != 0 || saltSize != 0) {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new IncrementalBLAKE2b(hashSize, key: ReadOnlySpan<byte>.Empty, p, s));
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
