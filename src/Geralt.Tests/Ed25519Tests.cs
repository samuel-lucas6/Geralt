namespace Geralt.Tests;

[TestClass]
public class Ed25519Tests
{
    // https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1
    public static IEnumerable<object[]> Rfc8032Ed25519TestVectors()
    {
        yield return new object[]
        {
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            "",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        };
        yield return new object[]
        {
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            "72",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        };
        yield return new object[]
        {
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            "af82",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        };
        yield return new object[]
        {
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
            "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
        };
    }

    // https://github.com/google/wycheproof/blob/master/testvectors_v1/ed25519_test.json
    public static IEnumerable<object[]> WycheproofTestVectors()
    {
        yield return new object[]
        {
            "647c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2b1d125e5538f38afbcc1c84e489521083041d24bc6240767029da063271a1ff0c",
            "313233343030",
            "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa"
        };
        yield return new object[]
        {
            "0971f86d2c9c78582524a103cb9cf949522ae528f8054dc20107d999be673ff4e25ebf2f2928766b1248bec6e91697775f8446639ede46ad4df4053000000010",
            "6a0bc2b0057cedfc0fa2e3f7f7d39279b30f454a69dfd1117c758d86b19d85e0",
            "100fdf47fb94f1536a4f7c3fda27383fa03375a8f527c537e6f1703c47f94f86"
        };
        yield return new object[]
        {
            "0100000000000000000000000000000000000000000000000000000000000000ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "3f",
            "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa"
        };
        yield return new object[]
        {
            "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab067654bce3832c2d76f8f6f5dafc08d9339d4eef676573336a5c51eb6f946b31d",
            "54657374",
            "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa"
        };
    }

    // https://www.rfc-editor.org/rfc/rfc8032.html#section-7.3
    public static IEnumerable<object[]> Rfc8032Ed25519phTestVectors()
    {
        yield return new object[]
        {
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
            "616263",
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
        };
    }

    public static IEnumerable<object[]> KeyPairInvalidParameterSizes()
    {
        yield return new object[] { Ed25519.PublicKeySize + 1, Ed25519.PrivateKeySize };
        yield return new object[] { Ed25519.PublicKeySize - 1, Ed25519.PrivateKeySize };
        yield return new object[] { Ed25519.PublicKeySize, Ed25519.PrivateKeySize + 1 };
        yield return new object[] { Ed25519.PublicKeySize, Ed25519.PrivateKeySize - 1 };
    }

    public static IEnumerable<object[]> SignInvalidParameterSizes()
    {
        yield return new object[] { Ed25519.SignatureSize + 1, 1, Ed25519.PrivateKeySize };
        yield return new object[] { Ed25519.SignatureSize - 1, 1, Ed25519.PrivateKeySize };
        yield return new object[] { Ed25519.SignatureSize, 1, Ed25519.PrivateKeySize + 1 };
        yield return new object[] { Ed25519.SignatureSize, 1, Ed25519.PrivateKeySize - 1 };
    }

    public static IEnumerable<object[]> VerifyInvalidParameterSizes()
    {
        yield return new object[] { Ed25519.SignatureSize + 1, 1, Ed25519.PublicKeySize };
        yield return new object[] { Ed25519.SignatureSize - 1, 1, Ed25519.PublicKeySize };
        yield return new object[] { Ed25519.SignatureSize, 1, Ed25519.PublicKeySize + 1 };
        yield return new object[] { Ed25519.SignatureSize, 1, Ed25519.PublicKeySize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, Ed25519.PublicKeySize);
        Assert.AreEqual(64, Ed25519.PrivateKeySize);
        Assert.AreEqual(64, Ed25519.SignatureSize);
        Assert.AreEqual(32, Ed25519.SeedSize);
    }

    [TestMethod]
    public void Incremental_Constants_Valid()
    {
        Assert.AreEqual(32, IncrementalEd25519ph.PublicKeySize);
        Assert.AreEqual(64, IncrementalEd25519ph.PrivateKeySize);
        Assert.AreEqual(64, IncrementalEd25519ph.SignatureSize);
    }

    [TestMethod]
    public void GenerateKeyPair_Valid()
    {
        Span<byte> pk = stackalloc byte[Ed25519.PublicKeySize];
        Span<byte> sk = stackalloc byte[Ed25519.PrivateKeySize];

        Ed25519.GenerateKeyPair(pk, sk);

        Assert.IsFalse(pk.SequenceEqual(new byte[pk.Length]));
        Assert.IsFalse(sk.SequenceEqual(new byte[sk.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(KeyPairInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void GenerateKeyPair_Invalid(int publicKeySize, int privateKeySize)
    {
        var pk = new byte[publicKeySize];
        var sk = new byte[privateKeySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(pk, sk));
    }

    [TestMethod]
    [DataRow("b5076a8474a832daee4dd5b4040983b6623b5f344aca57d4d6ee4baf3f259e6e", "421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedeeb5076a8474a832daee4dd5b4040983b6623b5f344aca57d4d6ee4baf3f259e6e", "421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee")]
    public void GenerateKeyPair_Seeded_Valid(string publicKey, string privateKey, string seed)
    {
        Span<byte> pk = stackalloc byte[Ed25519.PublicKeySize];
        Span<byte> sk = stackalloc byte[Ed25519.PrivateKeySize];
        Span<byte> s = Convert.FromHexString(seed);

        Ed25519.GenerateKeyPair(pk, sk, s);

        Assert.AreEqual(publicKey, Convert.ToHexString(pk).ToLower());
        Assert.AreEqual(privateKey, Convert.ToHexString(sk).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(KeyPairInvalidParameterSizes), DynamicDataSourceType.Method)]
    [DataRow(Ed25519.PublicKeySize, Ed25519.PrivateKeySize, Ed25519.SeedSize + 1)]
    [DataRow(Ed25519.PublicKeySize, Ed25519.PrivateKeySize, Ed25519.SeedSize - 1)]
    public void GenerateKeyPair_Seeded_Invalid(int publicKeySize, int privateKeySize, int seedSize = Ed25519.SeedSize)
    {
        var pk = new byte[publicKeySize];
        var sk = new byte[privateKeySize];
        var s = new byte[seedSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GenerateKeyPair(pk, sk, s));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519TestVectors), DynamicDataSourceType.Method)]
    public void ComputePublicKey_Valid(string signature, string message, string privateKey)
    {
        Span<byte> pk = stackalloc byte[Ed25519.PublicKeySize];
        Span<byte> sk = Convert.FromHexString(privateKey);

        Ed25519.ComputePublicKey(pk, sk);

        Assert.AreEqual(privateKey[(privateKey.Length / 2)..], Convert.ToHexString(pk).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(KeyPairInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ComputePublicKey_Invalid(int publicKeySize, int privateKeySize)
    {
        var pk = new byte[publicKeySize];
        var sk = new byte[privateKeySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.ComputePublicKey(pk, sk));
    }

    [TestMethod]
    [DataRow("25c704c594b88afc00a76b69d1ed2b984d7e22550f3ed0802d04fbcd07d38d47", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")]
    public void GetX25519PublicKey_Valid(string x25519PublicKey, string ed25519PublicKey)
    {
        Span<byte> x = stackalloc byte[X25519.PublicKeySize];
        Span<byte> e = Convert.FromHexString(ed25519PublicKey);

        Ed25519.GetX25519PublicKey(x, e);

        Assert.AreEqual(x25519PublicKey, Convert.ToHexString(x).ToLower());
    }

    [TestMethod]
    [DataRow(X25519.PublicKeySize + 1, Ed25519.PublicKeySize)]
    [DataRow(X25519.PublicKeySize - 1, Ed25519.PublicKeySize)]
    [DataRow(X25519.PublicKeySize, Ed25519.PublicKeySize + 1)]
    [DataRow(X25519.PublicKeySize, Ed25519.PublicKeySize - 1)]
    public void GetX25519PublicKey_Invalid(int x25519PublicKeySize, int ed25519PublicKeySize)
    {
        var x = new byte[x25519PublicKeySize];
        var e = new byte[ed25519PublicKeySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GetX25519PublicKey(x, e));
    }

    [TestMethod]
    [DataRow("68bd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e51", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")]
    public void GetX25519PrivateKey_Valid(string x25519PrivateKey, string ed25519PrivateKey)
    {
        Span<byte> x = stackalloc byte[X25519.PrivateKeySize];
        Span<byte> e = Convert.FromHexString(ed25519PrivateKey);

        Ed25519.GetX25519PrivateKey(x, e);

        Assert.AreEqual(x25519PrivateKey, Convert.ToHexString(x).ToLower());
    }

    [TestMethod]
    [DataRow(X25519.PrivateKeySize + 1, Ed25519.PrivateKeySize)]
    [DataRow(X25519.PrivateKeySize - 1, Ed25519.PrivateKeySize)]
    [DataRow(X25519.PrivateKeySize, Ed25519.PrivateKeySize + 1)]
    [DataRow(X25519.PrivateKeySize, Ed25519.PrivateKeySize - 1)]
    public void GetX25519PrivateKey_Invalid(int x25519PrivateKeySize, int ed25519PrivateKeySize)
    {
        var x = new byte[x25519PrivateKeySize];
        var e = new byte[ed25519PrivateKeySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.GetX25519PrivateKey(x, e));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519TestVectors), DynamicDataSourceType.Method)]
    public void Sign_Valid(string signature, string message, string privateKey)
    {
        Span<byte> s = stackalloc byte[Ed25519.SignatureSize];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> sk = Convert.FromHexString(privateKey);

        Ed25519.Sign(s, m, sk);

        Assert.AreEqual(signature, Convert.ToHexString(s).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(SignInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Sign_Invalid(int signatureSize, int messageSize, int privateKeySize)
    {
        var s = new byte[signatureSize];
        var m = new byte[messageSize];
        var sk = new byte[privateKeySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Sign(s, m, sk));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519TestVectors), DynamicDataSourceType.Method)]
    public void Verify_Valid(string signature, string message, string privateKey)
    {
        Span<byte> s = Convert.FromHexString(signature);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> pk = Convert.FromHexString(privateKey)[^Ed25519.PublicKeySize..];

        bool valid = Ed25519.Verify(s, m, pk);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(WycheproofTestVectors), DynamicDataSourceType.Method)]
    public void Verify_Tampered(string signature, string message, string publicKey)
    {
        Span<byte> s = Convert.FromHexString(signature);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> pk = Convert.FromHexString(publicKey);

        bool valid = Ed25519.Verify(s, m, pk);

        Assert.IsFalse(valid);
    }

    [TestMethod]
    [DynamicData(nameof(VerifyInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Verify_Invalid(int signatureSize, int messageSize, int publicKeySize)
    {
        var s = new byte[signatureSize];
        var m = new byte[messageSize];
        var pk = new byte[publicKeySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ed25519.Verify(s, m, pk));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Sign_Valid(string signature, string message, string privateKey)
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
    public void Incremental_Sign_Reinitialize_Valid(string signature, string message, string privateKey)
    {
        Span<byte> s = stackalloc byte[IncrementalEd25519ph.SignatureSize];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> sk = Convert.FromHexString(privateKey);

        using var ed25519ph = new IncrementalEd25519ph();
        ed25519ph.Update(m);
        ed25519ph.Finalize(s, sk);
        s.Clear();
        ed25519ph.Reinitialize();
        ed25519ph.Update(m);
        ed25519ph.Finalize(s, sk);

        Assert.AreEqual(signature, Convert.ToHexString(s).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(SignInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Incremental_Sign_Invalid(int signatureSize, int messageSize, int privateKeySize)
    {
        var s = new byte[signatureSize];
        var m = new byte[messageSize];
        var sk = new byte[privateKeySize];

        using var ed25519ph = new IncrementalEd25519ph();
        ed25519ph.Update(m);

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ed25519ph.Finalize(s, sk));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Sign_InvalidOperation(string signature, string message, string privateKey)
    {
        var s = new byte[IncrementalEd25519ph.SignatureSize];
        var m = Convert.FromHexString(message);
        var sk = Convert.FromHexString(privateKey);
        var pk = sk[^Ed25519.PublicKeySize..];

        using var ed25519ph = new IncrementalEd25519ph();
        ed25519ph.Update(m);
        ed25519ph.Finalize(s, sk);

        Assert.ThrowsException<InvalidOperationException>(() => ed25519ph.Update(m));
        Assert.ThrowsException<InvalidOperationException>(() => ed25519ph.Finalize(s, sk));
        Assert.ThrowsException<InvalidOperationException>(() => ed25519ph.FinalizeAndVerify(s, pk));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Verify_Valid(string signature, string message, string privateKey)
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
    public void Incremental_Verify_Reinitialize_Valid(string signature, string message, string privateKey)
    {
        Span<byte> s = Convert.FromHexString(signature);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> pk = Convert.FromHexString(privateKey)[^Ed25519.PublicKeySize..];

        using var ed25519ph = new IncrementalEd25519ph();
        ed25519ph.Update(m);
        ed25519ph.FinalizeAndVerify(s, pk);
        ed25519ph.Reinitialize();
        ed25519ph.Update(m);
        bool valid = ed25519ph.FinalizeAndVerify(s, pk);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Verify_Tampered(string signature, string message, string privateKey)
    {
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(signature),
            Convert.FromHexString(message),
            Convert.FromHexString(privateKey)[^Ed25519.PublicKeySize..]
        };

        foreach (var param in parameters.Where(param => param.Length != 0)) {
            param[0]++;
            using var ed25519ph = new IncrementalEd25519ph();
            ed25519ph.Update(parameters[1]);
            bool valid = ed25519ph.FinalizeAndVerify(parameters[0], parameters[2]);
            param[0]--;
            Assert.IsFalse(valid);
        }
    }

    [TestMethod]
    [DynamicData(nameof(VerifyInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Incremental_Verify_Invalid(int signatureSize, int messageSize, int publicKeySize)
    {
        var s = new byte[signatureSize];
        var m = new byte[messageSize];
        var pk = new byte[publicKeySize];

        using var ed25519ph = new IncrementalEd25519ph();
        ed25519ph.Update(m);

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ed25519ph.FinalizeAndVerify(s, pk));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8032Ed25519phTestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Verify_InvalidOperation(string signature, string message, string privateKey)
    {
        var s = Convert.FromHexString(signature);
        var m = Convert.FromHexString(message);
        var sk = Convert.FromHexString(privateKey);
        var pk = sk[^Ed25519.PublicKeySize..];

        using var ed25519ph = new IncrementalEd25519ph();
        ed25519ph.Update(m);
        ed25519ph.FinalizeAndVerify(s, pk);

        Assert.ThrowsException<InvalidOperationException>(() => ed25519ph.Update(m));
        Assert.ThrowsException<InvalidOperationException>(() => ed25519ph.Finalize(s, sk));
        Assert.ThrowsException<InvalidOperationException>(() => ed25519ph.FinalizeAndVerify(s, pk));
    }
}
