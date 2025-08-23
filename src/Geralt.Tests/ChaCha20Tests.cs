namespace Geralt.Tests;

[TestClass]
public class ChaCha20Tests
{
    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.6.2
    // https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.4
    public static IEnumerable<object[]> Rfc8439FillTestVectors()
    {
        yield return
        [
            "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646",
            "000000000001020304050607",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        ];
        yield return
        [
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
            "000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000"
        ];
        yield return
        [
            "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739",
            "000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000001"
        ];
        yield return
        [
            "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae",
            "000000000000000000000002",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
        ];
    }

    public static IEnumerable<object[]> FillInvalidParameterSizes()
    {
        yield return [0, ChaCha20.NonceSize, ChaCha20.KeySize];
        yield return [ChaCha20.BlockSize, ChaCha20.NonceSize + 1, ChaCha20.KeySize];
        yield return [ChaCha20.BlockSize, ChaCha20.NonceSize - 1, ChaCha20.KeySize];
        yield return [ChaCha20.BlockSize, ChaCha20.NonceSize, ChaCha20.KeySize + 1];
        yield return [ChaCha20.BlockSize, ChaCha20.NonceSize, ChaCha20.KeySize - 1];
    }

    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.4.2
    // https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.2
    public static IEnumerable<object[]> Rfc8439EncryptTestVectors()
    {
        yield return
        [
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "000000000000004a00000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            (uint)1
        ];
        yield return
        [
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            (uint)0
        ];
        yield return
        [
            "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
            "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
            "000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000001",
            (uint)1
        ];
        yield return
        [
            "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
            "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
            "000000000000000000000002",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            (uint)42
        ];
    }

    public static IEnumerable<object[]> EncryptInvalidParameterSizes()
    {
        yield return [ChaCha20.BlockSize, ChaCha20.BlockSize + 1, ChaCha20.NonceSize, ChaCha20.KeySize, (uint)0];
        yield return [ChaCha20.BlockSize, ChaCha20.BlockSize - 1, ChaCha20.NonceSize, ChaCha20.KeySize, (uint)0];
        yield return [ChaCha20.BlockSize, ChaCha20.BlockSize, ChaCha20.NonceSize + 1, ChaCha20.KeySize, (uint)0];
        yield return [ChaCha20.BlockSize, ChaCha20.BlockSize, ChaCha20.NonceSize - 1, ChaCha20.KeySize, (uint)0];
        yield return [ChaCha20.BlockSize, ChaCha20.BlockSize, ChaCha20.NonceSize, ChaCha20.KeySize + 1, (uint)0];
        yield return [ChaCha20.BlockSize, ChaCha20.BlockSize, ChaCha20.NonceSize, ChaCha20.KeySize - 1, (uint)0];
        yield return [ChaCha20.BlockSize, ChaCha20.BlockSize, ChaCha20.NonceSize, ChaCha20.KeySize, uint.MaxValue];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, ChaCha20.KeySize);
        Assert.AreEqual(12, ChaCha20.NonceSize);
        Assert.AreEqual(64, ChaCha20.BlockSize);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439FillTestVectors), DynamicDataSourceType.Method)]
    public void Fill_Valid(string buffer, string nonce, string key)
    {
        Span<byte> b = stackalloc byte[buffer.Length / 2];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        ChaCha20.Fill(b, n, k);

        Assert.AreEqual(buffer, Convert.ToHexString(b).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(FillInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Fill_Invalid(int bufferSize, int nonceSize, int keySize)
    {
        var b = new byte[bufferSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ChaCha20.Fill(b, n, k));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439EncryptTestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, uint counter)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        ChaCha20.Encrypt(c, p, n, k, counter);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, uint counter)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        if (counter < uint.MaxValue) {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ChaCha20.Encrypt(c, p, n, k, counter));
        }
        else {
            Assert.ThrowsExactly<CryptographicException>(() => ChaCha20.Encrypt(c, p, n, k, counter));
        }
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439EncryptTestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, uint counter)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        ChaCha20.Decrypt(p, c, n, k, counter);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, uint counter)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        if (counter < uint.MaxValue) {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ChaCha20.Decrypt(p, c, n, k, counter));
        }
        else {
            Assert.ThrowsExactly<CryptographicException>(() => ChaCha20.Decrypt(p, c, n, k, counter));
        }
    }
}
