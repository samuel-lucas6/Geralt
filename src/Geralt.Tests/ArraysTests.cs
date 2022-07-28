using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class ArraysTests
{
    private static readonly byte[] Array1 = {0x00, 0x01, 0x02, 0x03};
    private static readonly byte[] Array2 = {0x04, 0x05, 0x06, 0x07};

    [TestMethod]
    public void Concat_TwoArrays()
    {
        byte[] concatenated = Arrays.Concat(Array1, Array2);
        var expected = new byte[Array1.Length + Array2.Length];
        Array.Copy(Array1, expected, Array1.Length);
        Array.Copy(Array2, sourceIndex: 0, expected, destinationIndex: Array1.Length, Array2.Length);
        Assert.IsTrue(concatenated.SequenceEqual(expected));
    }
    
    [TestMethod]
    public void Concat_SingleArray()
    {
        byte[] array = Arrays.Concat(Array1);
        Assert.IsTrue(array.SequenceEqual(Array1));
    }
    
    [TestMethod]
    public void Slice()
    {
        Span<byte> slice = Arrays.Slice(Array1, sourceIndex: 1, length: Array1.Length / 2);
        Span<byte> expected = Array1.AsSpan().Slice(start: 1, length: Array1.Length / 2);
        Assert.IsTrue(slice.SequenceEqual(expected));
    }
}