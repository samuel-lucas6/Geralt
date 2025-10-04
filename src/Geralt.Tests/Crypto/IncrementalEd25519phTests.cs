namespace Geralt.Tests;

[TestClass]
public class IncrementalEd25519phTests
{
    // https://www.rfc-editor.org/rfc/rfc8032.html#section-7.3
    public static IEnumerable<object[]> Rfc8032Ed25519phTestVectors()
    {
        yield return
        [
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
            "616263",
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
        ];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, IncrementalEd25519ph.PublicKeySize);
        Assert.AreEqual(64, IncrementalEd25519ph.PrivateKeySize);
        Assert.AreEqual(64, IncrementalEd25519ph.SignatureSize);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Sign_Valid(string signature, string message, string privateKey)
    {
        Span<byte> s = stackalloc byte[IncrementalEd25519ph.SignatureSize];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> sk = Convert.FromHexString(privateKey);

        using var ed25519ph = new IncrementalEd25519ph();
        if (m.Length > 1) {
            ed25519ph.Update(m[..(m.Length / 2)]);
            ed25519ph.Update(m[(m.Length / 2)..]);
        }
        else {
            ed25519ph.Update(m);
        }
        ed25519ph.Finalize(s, sk);

        Assert.AreEqual(signature, Convert.ToHexString(s).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Reinitialize_Valid(string signature, string message, string privateKey)
    {
        Span<byte> s = stackalloc byte[IncrementalEd25519ph.SignatureSize];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> sk = Convert.FromHexString(privateKey);
        Span<byte> pk = sk[^Ed25519.PublicKeySize..];

        using var ed25519ph = new IncrementalEd25519ph();
        ed25519ph.Update(m);
        ed25519ph.Finalize(s, sk);
        ed25519ph.Reinitialize();
        ed25519ph.Update(m);
        bool valid = ed25519ph.FinalizeAndVerify(s, pk);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Verify_Valid(string signature, string message, string privateKey)
    {
        Span<byte> s = Convert.FromHexString(signature);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> pk = Convert.FromHexString(privateKey)[^Ed25519.PublicKeySize..];

        using var ed25519ph = new IncrementalEd25519ph();
        if (m.Length > 1) {
            ed25519ph.Update(m[..(m.Length / 2)]);
            ed25519ph.Update(m[(m.Length / 2)..]);
        }
        else {
            ed25519ph.Update(m);
        }
        bool valid = ed25519ph.FinalizeAndVerify(s, pk);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Verify_Tampered(string signature, string message, string privateKey)
    {
        var parameters = new Dictionary<string, byte[]>
        {
            { "s", Convert.FromHexString(signature) },
            { "m", Convert.FromHexString(message) },
            { "pk", Convert.FromHexString(privateKey)[^Ed25519.PublicKeySize..] }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            using var ed25519ph = new IncrementalEd25519ph();
            ed25519ph.Update(parameters["m"]);
            bool valid = ed25519ph.FinalizeAndVerify(parameters["s"], parameters["pk"]);
            Assert.IsFalse(valid);
            param[0]--;
        }
    }

    [TestMethod]
    [DynamicData(nameof(Ed25519Tests.SignInvalidParameterSizes), typeof(Ed25519Tests))]
    public void Incremental_Invalid(int signatureSize, int messageSize, int privateKeySize)
    {
        var s = new byte[signatureSize];
        var m = new byte[messageSize];
        var sk = new byte[privateKeySize];
        var pk = new byte[privateKeySize - Ed25519.PublicKeySize];

        using var ed25519ph = new IncrementalEd25519ph();
        ed25519ph.Update(m);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ed25519ph.Finalize(s, sk));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ed25519ph.FinalizeAndVerify(s, pk));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Incremental_InvalidOperation(string signature, string message, string privateKey)
    {
        var s = new byte[IncrementalEd25519ph.SignatureSize];
        var m = Convert.FromHexString(message);
        var sk = Convert.FromHexString(privateKey);
        var pk = sk[^Ed25519.PublicKeySize..];

        using var ed25519ph = new IncrementalEd25519ph();
        ed25519ph.Update(m);
        ed25519ph.Finalize(s, sk);

        Assert.ThrowsExactly<InvalidOperationException>(() => ed25519ph.Update(m));
        Assert.ThrowsExactly<InvalidOperationException>(() => ed25519ph.Finalize(s, sk));
        Assert.ThrowsExactly<InvalidOperationException>(() => ed25519ph.FinalizeAndVerify(s, pk));

        ed25519ph.Reinitialize();
        ed25519ph.Update(m);
        ed25519ph.FinalizeAndVerify(s, pk);

        Assert.ThrowsExactly<InvalidOperationException>(() => ed25519ph.Update(m));
        Assert.ThrowsExactly<InvalidOperationException>(() => ed25519ph.Finalize(s, sk));
        Assert.ThrowsExactly<InvalidOperationException>(() => ed25519ph.FinalizeAndVerify(s, pk));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Disposed(string signature, string message, string privateKey)
    {
        var s = Convert.FromHexString(signature);
        var m = Convert.FromHexString(message);
        var sk = Convert.FromHexString(privateKey);
        var pk = sk[^Ed25519.PublicKeySize..];

        var ed25519ph = new IncrementalEd25519ph();
        ed25519ph.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => ed25519ph.Reinitialize());
        Assert.ThrowsExactly<ObjectDisposedException>(() => ed25519ph.Update(m));
        Assert.ThrowsExactly<ObjectDisposedException>(() => ed25519ph.Finalize(s, sk));
        Assert.ThrowsExactly<ObjectDisposedException>(() => ed25519ph.FinalizeAndVerify(s, pk));
        ed25519ph.Dispose();
    }
}
