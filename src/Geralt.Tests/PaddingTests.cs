using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class PaddingTests
{
    // Taken from NSec
    private static readonly byte[] Data = { 0x01, 0x02 };
    private static readonly byte[] PaddedData = { 0x01, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00 };
    private const int BlockSize = 8;
    private const int InvalidBlockSize = 0;
    
    [TestMethod]
    public void Pad_ValidInputs()
    {
        Span<byte> buffer = stackalloc byte[Padding.GetPaddedLength(Data.Length, BlockSize)];
        Padding.Pad(buffer, Data, BlockSize);
        Assert.IsTrue(buffer.SequenceEqual(PaddedData));
    }
    
    [TestMethod]
    public void Pad_EmptyData()
    {
        Span<byte> data = Array.Empty<byte>();
        Span<byte> buffer = stackalloc byte[Padding.GetPaddedLength(data.Length, BlockSize)];
        Padding.Pad(buffer, data, BlockSize);
        Assert.IsFalse(buffer.SequenceEqual(new byte[buffer.Length]));
    }
    
    [TestMethod]
    public void GetPaddedLength_InvalidDataLength()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Padding.GetPaddedLength(unpaddedLength: -1, BlockSize));
    }
    
    [TestMethod]
    public void GetPaddedLength_InvalidBlockSize()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Padding.GetPaddedLength(Data.Length, InvalidBlockSize));
    }
    
    [TestMethod]
    public void Pad_InvalidBuffer()
    {
        var buffer = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Padding.Pad(buffer, Data, BlockSize));
    }
    
    [TestMethod]
    public void Pad_InvalidBlockSize()
    {
        var buffer = new byte[Padding.GetPaddedLength(Data.Length, BlockSize)];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Padding.Pad(buffer, Data, InvalidBlockSize));
    }
    
    [TestMethod]
    public void GetUnpaddedLength_ValidInputs()
    {
        int unpaddedLength = Padding.GetUnpaddedLength(PaddedData, BlockSize);
        Assert.IsTrue(unpaddedLength == Data.Length);
    }
    
    [TestMethod]
    public void GetUnpaddedLength_CorruptedPadding()
    {
        var paddedData = PaddedData.ToArray();
        paddedData[2] = 0x00;
        Assert.ThrowsException<FormatException>(() => Padding.GetUnpaddedLength(paddedData, BlockSize));
    }

    [TestMethod]
    public void GetUnpaddedLength_InvalidData()
    {
        var paddedData = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Padding.GetUnpaddedLength(paddedData, BlockSize));
    }
    
    [TestMethod]
    public void GetUnpaddedLength_InvalidBlockSize()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Padding.GetUnpaddedLength(PaddedData, InvalidBlockSize));
    }
}