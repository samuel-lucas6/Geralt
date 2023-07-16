using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class PaddingTests
{
    // https://github.com/ektrah/nsec/blob/master/tests/Other/Iso78164PaddingTests.cs
    public static IEnumerable<object[]> NsecTestVectors()
    {
        yield return new object[] { "8000000000000000", "", 8 };
        yield return new object[] { "0180000000000000", "01", 8 };
        yield return new object[] { "0102800000000000", "0102", 8 };
        yield return new object[] { "0102038000000000", "010203", 8 };
        yield return new object[] { "0102030480000000", "01020304", 8 };
        yield return new object[] { "0102030405800000", "0102030405", 8 };
        yield return new object[] { "0102030405068000", "010203040506", 8 };
        yield return new object[] { "0102030405060780", "01020304050607", 8 };
        yield return new object[] { "01020304050607088000000000000000", "0102030405060708", 8 };
        yield return new object[] { "01020304050607080980000000000000", "010203040506070809", 8 };
        yield return new object[] { "0102030405060708090a800000000000", "0102030405060708090a", 8 };
        yield return new object[] { "0102030405060708090a0b8000000000", "0102030405060708090a0b", 8 };
        yield return new object[] { "0102030405060708090a0b0c80000000", "0102030405060708090a0b0c", 8 };
        yield return new object[] { "0102030405060708090a0b0c0d800000", "0102030405060708090a0b0c0d", 8 };
        yield return new object[] { "0102030405060708090a0b0c0d0e8000", "0102030405060708090a0b0c0d0e", 8 };
        yield return new object[] { "0102030405060708090a0b0c0d0e0f80", "0102030405060708090a0b0c0d0e0f", 8 };
    }

    [TestMethod]
    [DynamicData(nameof(NsecTestVectors), DynamicDataSourceType.Method)]
    public void Pad_Valid(string buffer, string data, int blockSize)
    {
        Span<byte> d = Convert.FromHexString(data);
        Span<byte> b = stackalloc byte[Padding.GetPaddedLength(d.Length, blockSize)];

        Padding.Pad(b, d, blockSize);

        Assert.AreEqual(buffer, Convert.ToHexString(b).ToLower());
    }

    [TestMethod]
    [DataRow(0, 1, 8)]
    [DataRow(1, 1, 0)]
    public void Pad_Invalid(int bufferSize, int dataSize, int blockSize)
    {
        var b = new byte[bufferSize];
        var d = new byte[dataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Padding.Pad(b, d, blockSize));
    }

    [TestMethod]
    [DataRow(-1, 8)]
    [DataRow(1, 0)]
    public void GetPaddedLength_Invalid(int unpaddedLength, int blockSize)
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Padding.GetPaddedLength(unpaddedLength, blockSize));
    }

    [TestMethod]
    [DataRow("8000000000000000")]
    public void Fill_Valid(string buffer)
    {
        Span<byte> b = stackalloc byte[buffer.Length / 2];

        Padding.Fill(b);

        Assert.AreEqual(buffer, Convert.ToHexString(b).ToLower());
    }

    [TestMethod]
    public void Fill_Invalid()
    {
        var b = Array.Empty<byte>();

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Padding.Fill(b));
    }

    [TestMethod]
    [DynamicData(nameof(NsecTestVectors), DynamicDataSourceType.Method)]
    public void GetUnpaddedLength_Valid(string paddedData, string data, int blockSize)
    {
        Span<byte> p = Convert.FromHexString(paddedData);

        int unpaddedLength = Padding.GetUnpaddedLength(p, blockSize);

        Assert.AreEqual(data.Length / 2, unpaddedLength);
    }

    [TestMethod]
    [DynamicData(nameof(NsecTestVectors), DynamicDataSourceType.Method)]
    public void GetUnpaddedLength_Tampered(string paddedData, string data, int blockSize)
    {
        var p = Convert.FromHexString(paddedData.Replace("80", "00"));

        Assert.ThrowsException<FormatException>(() => Padding.GetUnpaddedLength(p, blockSize));
    }

    [TestMethod]
    [DataRow(0, 8)]
    [DataRow(1, 0)]
    public void GetUnpaddedLength_Invalid(int paddedDataSize, int blockSize)
    {
        var p = new byte[paddedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Padding.GetUnpaddedLength(p, blockSize));
    }
}
