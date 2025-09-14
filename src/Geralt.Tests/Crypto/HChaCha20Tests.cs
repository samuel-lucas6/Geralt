namespace Geralt.Tests;

[TestClass]
public class HChaCha20Tests
{
    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, HChaCha20.OutputSize);
        Assert.AreEqual(32, HChaCha20.KeySize);
        Assert.AreEqual(16, HChaCha20.NonceSize);
        Assert.AreEqual(16, HChaCha20.PersonalizationSize);
    }

    [TestMethod]
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#section-2.2.1
    [DataRow("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000090000004a0000000031415927")]
    // https://github.com/chiefbiiko/hchacha20/blob/master/test_vectors.json
    [DataRow("934d941d78eb9bfc2f0376f7ccd4a11ecf0c6a44104618a9749ef47fe97037a2", "c49758f00003714c38f1d4972bde57ee8271f543b91e07ebce56b554eb7fa6a7", "31f0204e10cf4f2035f9e62bb5ba7303", "0d29b795c1ca70c1652e823364d32417")]
    public void DeriveKey_Valid(string outputKeyingMaterial, string inputKeyingMaterial, string nonce, string? personalization = null)
    {
        Span<byte> okm = stackalloc byte[HChaCha20.OutputSize];
        Span<byte> ikm = Convert.FromHexString(inputKeyingMaterial);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> p = personalization != null ? Convert.FromHexString(personalization) : Span<byte>.Empty;

        HChaCha20.DeriveKey(okm, ikm, n, p);

        Assert.AreEqual(outputKeyingMaterial, Convert.ToHexString(okm).ToLower());
    }

    [TestMethod]
    // https://link.springer.com/article/10.1007/s00145-018-9297-9 - personalization (ChaCha constant) symmetry
    [DataRow("00000000000000000000000000000000")]
    [DataRow("11111111111111111111111111111111")]
    [DataRow("00000000111111110000000011111111")]
    public void DeriveKey_Tampered(string personalization)
    {
        var okm = new byte[HChaCha20.OutputSize];
        var ikm = new byte[HChaCha20.KeySize];
        var n = new byte[HChaCha20.NonceSize];
        var p = Convert.FromHexString(personalization);

        Assert.ThrowsExactly<FormatException>(() => HChaCha20.DeriveKey(okm, ikm, n, p));
    }

    [TestMethod]
    [DataRow(HChaCha20.OutputSize + 1, HChaCha20.KeySize, HChaCha20.NonceSize, HChaCha20.PersonalizationSize)]
    [DataRow(HChaCha20.OutputSize - 1, HChaCha20.KeySize, HChaCha20.NonceSize, HChaCha20.PersonalizationSize)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize + 1, HChaCha20.NonceSize, HChaCha20.PersonalizationSize)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize - 1, HChaCha20.NonceSize, HChaCha20.PersonalizationSize)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize, HChaCha20.NonceSize + 1, HChaCha20.PersonalizationSize)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize, HChaCha20.NonceSize - 1, HChaCha20.PersonalizationSize)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize, HChaCha20.NonceSize, HChaCha20.PersonalizationSize + 1)]
    [DataRow(HChaCha20.OutputSize, HChaCha20.KeySize, HChaCha20.NonceSize, HChaCha20.PersonalizationSize - 1)]
    public void DeriveKey_Invalid(int outputKeyingMaterialSize, int inputKeyingMaterialSize, int nonceSize, int personalizationSize)
    {
        var okm = new byte[outputKeyingMaterialSize];
        var ikm = new byte[inputKeyingMaterialSize];
        var n = new byte[nonceSize];
        var p = new byte[personalizationSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => HChaCha20.DeriveKey(okm, ikm, n, p));
    }
}
