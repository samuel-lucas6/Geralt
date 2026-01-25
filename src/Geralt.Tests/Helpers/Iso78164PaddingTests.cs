namespace Geralt.Tests;

[TestClass]
public class Iso78164PaddingTests
{
    // https://github.com/ektrah/nsec/blob/master/tests/Other/Iso78164PaddingTests.cs
    public static IEnumerable<object[]> NsecTestVectors()
    {
        yield return ["8000000000000000", "", 8];
        yield return ["0180000000000000", "01", 8];
        yield return ["0102800000000000", "0102", 8];
        yield return ["0102038000000000", "010203", 8];
        yield return ["0102030480000000", "01020304", 8];
        yield return ["0102030405800000", "0102030405", 8];
        yield return ["0102030405068000", "010203040506", 8];
        yield return ["0102030405060780", "01020304050607", 8];
        yield return ["01020304050607088000000000000000", "0102030405060708", 8];
        yield return ["01020304050607080980000000000000", "010203040506070809", 8];
        yield return ["0102030405060708090a800000000000", "0102030405060708090a", 8];
        yield return ["0102030405060708090a0b8000000000", "0102030405060708090a0b", 8];
        yield return ["0102030405060708090a0b0c80000000", "0102030405060708090a0b0c", 8];
        yield return ["0102030405060708090a0b0c0d800000", "0102030405060708090a0b0c0d", 8];
        yield return ["0102030405060708090a0b0c0d0e8000", "0102030405060708090a0b0c0d0e", 8];
        yield return ["0102030405060708090a0b0c0d0e0f80", "0102030405060708090a0b0c0d0e0f", 8];
    }

    [TestMethod]
    [DynamicData(nameof(NsecTestVectors))]
    public void Pad_Valid(string buffer, string data, int blockSize)
    {
        Span<byte> d = Convert.FromHexString(data);
        Span<byte> b = stackalloc byte[Iso78164Padding.GetPaddedBufferSize(d, blockSize)];

        Iso78164Padding.Pad(b, d, blockSize);

        Assert.AreEqual(buffer, Convert.ToHexString(b).ToLower());
    }

    [TestMethod]
    [DataRow(0, 1, 8)]
    [DataRow(8 + 1, 1, 8)]
    [DataRow(8 - 1, 1, 8)]
    [DataRow(1, 1, 0)]
    public void Pad_Invalid(int bufferSize, int dataSize, int blockSize)
    {
        var b = new byte[bufferSize];
        var d = new byte[dataSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Iso78164Padding.Pad(b, d, blockSize));
    }

    [TestMethod]
    [DataRow(8, 0, 8)]
    [DataRow(8, 7, 8)]
    [DataRow(16, 8, 8)]
    [DataRow(16, 9, 8)]
    public void GetPaddedBufferSize_Valid(int bufferSize, int dataSize, int blockSize)
    {
        Span<byte> d = stackalloc byte[dataSize];

        int paddedSize = Iso78164Padding.GetPaddedBufferSize(d, blockSize);

        Assert.AreEqual(bufferSize, paddedSize);
    }

    [TestMethod]
    [DataRow(1, 0)]
    public void GetPaddedBufferSize_Invalid(int dataSize, int blockSize)
    {
        var d = new byte[dataSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Iso78164Padding.GetPaddedBufferSize(d, blockSize));
    }

    [TestMethod]
    [DataRow("8000000000000000")]
    [DataRow("80000000000000000000000000000000")]
    public void Fill_Valid(string buffer)
    {
        Span<byte> b = stackalloc byte[buffer.Length / 2];

        Iso78164Padding.Fill(b);

        Assert.AreEqual(buffer, Convert.ToHexString(b).ToLower());
    }

    [TestMethod]
    public void Fill_Invalid()
    {
        var b = Array.Empty<byte>();

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Iso78164Padding.Fill(b));
    }

    [TestMethod]
    [DynamicData(nameof(NsecTestVectors))]
    public void GetUnpaddedBufferSize_Valid(string paddedData, string data, int blockSize)
    {
        Span<byte> pd = Convert.FromHexString(paddedData);

        int unpaddedSize = Iso78164Padding.GetUnpaddedBufferSize(pd, blockSize);

        Assert.AreEqual(data.Length / 2, unpaddedSize);
    }

    [TestMethod]
    [DataRow("0102030000000000", 8)]
    [DataRow("0102038010000000", 8)]
    [DataRow("0102038000010000", 8)]
    [DataRow("0102038000000001", 8)]
    public void GetUnpaddedBufferSize_Tampered(string paddedData, int blockSize)
    {
        var pd = Convert.FromHexString(paddedData);

        Assert.ThrowsExactly<FormatException>(() => Iso78164Padding.GetUnpaddedBufferSize(pd, blockSize));
    }

    [TestMethod]
    [DataRow(0, 8)]
    [DataRow(1, 0)]
    public void GetUnpaddedBufferSize_Invalid(int paddedDataSize, int blockSize)
    {
        var pd = new byte[paddedDataSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Iso78164Padding.GetUnpaddedBufferSize(pd, blockSize));
    }
}
