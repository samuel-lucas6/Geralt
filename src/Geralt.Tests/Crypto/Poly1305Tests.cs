namespace Geralt.Tests;

[TestClass]
public class Poly1305Tests
{
    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.5.2
    // https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.3
    public static IEnumerable<object[]> Rfc8439TestVectors()
    {
        yield return
        [
            "a8061dc1305136c6c22b8baf0c0127a9",
            "43727970746f6772617068696320466f72756d2052657365617263682047726f7570",
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
        ];
        yield return
        [
            "f3477e7cd95417af89a6b8794c310cf0",
            "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
            "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000"
        ];
        yield return
        [
            "4541669a7eaaee61e708dc7cbcc5eb62",
            "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
        ];
        yield return
        [
            "03000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff",
            "0200000000000000000000000000000000000000000000000000000000000000"
        ];
        yield return
        [
            "03000000000000000000000000000000",
            "02000000000000000000000000000000",
            "02000000000000000000000000000000ffffffffffffffffffffffffffffffff"
        ];
        yield return
        [
            "05000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000"
        ];
        yield return
        [
            "00000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101",
            "0100000000000000000000000000000000000000000000000000000000000000"
        ];
        yield return
        [
            "faffffffffffffffffffffffffffffff",
            "fdffffffffffffffffffffffffffffff",
            "0200000000000000000000000000000000000000000000000000000000000000"
        ];
        yield return
        [
            "14000000000000005500000000000000",
            "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000",
            "0100000000000000040000000000000000000000000000000000000000000000"
        ];
        yield return
        [
            "13000000000000000000000000000000",
            "e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000",
            "0100000000000000040000000000000000000000000000000000000000000000"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [Poly1305.TagSize + 1, Poly1305.BlockSize, Poly1305.KeySize];
        yield return [Poly1305.TagSize - 1, Poly1305.BlockSize, Poly1305.KeySize];
        yield return [Poly1305.TagSize, Poly1305.BlockSize, Poly1305.KeySize + 1];
        yield return [Poly1305.TagSize, Poly1305.BlockSize, Poly1305.KeySize - 1];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, Poly1305.KeySize);
        Assert.AreEqual(16, Poly1305.TagSize);
        Assert.AreEqual(16, Poly1305.BlockSize);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439TestVectors))]
    public void ComputeTag_Valid(string tag, string message, string oneTimeKey)
    {
        Span<byte> t = stackalloc byte[Poly1305.TagSize];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(oneTimeKey);

        Poly1305.ComputeTag(t, m, k);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes))]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Poly1305.ComputeTag(t, m, k));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439TestVectors))]
    public void VerifyTag_Valid(string tag, string message, string oneTimeKey)
    {
        Span<byte> t = Convert.FromHexString(tag);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(oneTimeKey);

        bool valid = Poly1305.VerifyTag(t, m, k);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439TestVectors))]
    public void VerifyTag_Tampered(string tag, string message, string oneTimeKey)
    {
        var parameters = new Dictionary<string, byte[]>
        {
            { "t", Convert.FromHexString(tag) },
            { "m", Convert.FromHexString(message) },
            { "k", Convert.FromHexString(oneTimeKey) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            bool valid = Poly1305.VerifyTag(parameters["t"], parameters["m"], parameters["k"]);
            param[0]--;
            Assert.IsFalse(valid);
        }
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes))]
    public void VerifyTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Poly1305.VerifyTag(t, m, k));
    }
}
