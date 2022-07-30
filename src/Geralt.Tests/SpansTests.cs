using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class SpansTests
{
    private static readonly byte[] Array1 = {0x00, 0x01, 0x02, 0x03};
    private static readonly byte[] Array2 = {0x04, 0x05, 0x06, 0x07};
    private static readonly byte[] Array3 = {0x08, 0x09, 0x10, 0x11};
    private static readonly byte[] Array4 = {0x12, 0x13, 0x14, 0x15};
    private static readonly byte[] Array5 = {0x16, 0x17, 0x18, 0x19};
    private static readonly byte[] Array6 = {0x20, 0x21, 0x22, 0x23};

    [TestMethod]
    public void Concat_TwoSpans()
    {
        Span<byte> concatenated = stackalloc byte[Array1.Length + Array2.Length];
        Spans.Concat(concatenated, Array1, Array2);
        Span<byte> expected = Arrays.Concat(Array1, Array2);
        Assert.IsTrue(concatenated.SequenceEqual(expected));
    }
    
    [TestMethod]
    public void Concat_ThreeSpans()
    {
        Span<byte> concatenated = stackalloc byte[Array1.Length + Array2.Length + Array3.Length];
        Spans.Concat(concatenated, Array1, Array2, Array3);
        Span<byte> expected = Arrays.Concat(Array1, Array2, Array3);
        Assert.IsTrue(concatenated.SequenceEqual(expected));
    }
    
    [TestMethod]
    public void Concat_FourSpans()
    {
        Span<byte> concatenated = stackalloc byte[Array1.Length + Array2.Length + Array3.Length + Array4.Length];
        Spans.Concat(concatenated, Array1, Array2, Array3, Array4);
        Span<byte> expected = Arrays.Concat(Array1, Array2, Array3, Array4);
        Assert.IsTrue(concatenated.SequenceEqual(expected));
    }
    
    [TestMethod]
    public void Concat_FiveSpans()
    {
        Span<byte> concatenated = stackalloc byte[Array1.Length + Array2.Length + Array3.Length + Array4.Length + Array5.Length];
        Spans.Concat(concatenated, Array1, Array2, Array3, Array4, Array5);
        Span<byte> expected = Arrays.Concat(Array1, Array2, Array3, Array4, Array5);
        Assert.IsTrue(concatenated.SequenceEqual(expected));
    }
    
    [TestMethod]
    public void Concat_SixSpans()
    {
        Span<byte> concatenated = stackalloc byte[Array1.Length + Array2.Length + Array3.Length + Array4.Length + Array5.Length + Array6.Length];
        Spans.Concat(concatenated, Array1, Array2, Array3, Array4, Array5, Array6);
        Span<byte> expected = Arrays.Concat(Array1, Array2, Array3, Array4, Array5, Array6);
        Assert.IsTrue(concatenated.SequenceEqual(expected));
    }
}