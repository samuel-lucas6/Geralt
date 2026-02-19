using System.Numerics;

namespace Geralt.Tests;

[TestClass]
public class ValidationTests
{
    [TestMethod]
    [DataRow(0, 0)]
    [DataRow(32, 32)]
    public void EqualTo_Valid(int value, int required)
    {
        Validation.EqualTo(nameof(value), (sbyte)value, (sbyte)required);
        Validation.EqualTo(nameof(value), (byte)value, (byte)required);
        Validation.EqualTo(nameof(value), (short)value, (short)required);
        Validation.EqualTo(nameof(value), (ushort)value, (ushort)required);
        Validation.EqualTo(nameof(value), (int)value, (int)required);
        Validation.EqualTo(nameof(value), (uint)value, (uint)required);
        Validation.EqualTo(nameof(value), (long)value, (long)required);
        Validation.EqualTo(nameof(value), (ulong)value, (ulong)required);
        Validation.EqualTo(nameof(value), (IntPtr)value, (IntPtr)required);
        Validation.EqualTo(nameof(value), (UIntPtr)value, (UIntPtr)required);
        Validation.EqualTo(nameof(value), (Int128)value, (Int128)required);
        Validation.EqualTo(nameof(value), (UInt128)value, (UInt128)required);
        Validation.EqualTo(nameof(value), new BigInteger(value), new BigInteger(required));
    }

    [TestMethod]
    [DataRow(0, 1)]
    [DataRow(2, 1)]
    public void EqualTo_Invalid(int value, int required)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (sbyte)value, (sbyte)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (byte)value, (byte)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (short)value, (short)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (ushort)value, (ushort)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (int)value, (int)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (uint)value, (uint)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (long)value, (long)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (ulong)value, (ulong)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (IntPtr)value, (IntPtr)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (UIntPtr)value, (UIntPtr)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (Int128)value, (Int128)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), (UInt128)value, (UInt128)required));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.EqualTo(nameof(value), new BigInteger(value), new BigInteger(required)));
    }

    [TestMethod]
    [DataRow(16, 16, 64)]
    [DataRow(32, 16, 64)]
    [DataRow(64, 16, 64)]
    public void Between_Valid(int value, int min, int max)
    {
        Validation.Between(nameof(value), (sbyte)value, (sbyte)min, (sbyte)max);
        Validation.Between(nameof(value), (byte)value, (byte)min, (byte)max);
        Validation.Between(nameof(value), (short)value, (short)min, (short)max);
        Validation.Between(nameof(value), (ushort)value, (ushort)min, (ushort)max);
        Validation.Between(nameof(value), (int)value, (int)min, (int)max);
        Validation.Between(nameof(value), (uint)value, (uint)min, (uint)max);
        Validation.Between(nameof(value), (long)value, (long)min, (long)max);
        Validation.Between(nameof(value), (ulong)value, (ulong)min, (ulong)max);
        Validation.Between(nameof(value), (IntPtr)value, (IntPtr)min, (IntPtr)max);
        Validation.Between(nameof(value), (UIntPtr)value, (UIntPtr)min, (UIntPtr)max);
        Validation.Between(nameof(value), (Int128)value, (Int128)min, (Int128)max);
        Validation.Between(nameof(value), (UInt128)value, (UInt128)min, (UInt128)max);
        Validation.Between(nameof(value), new BigInteger(value), new BigInteger(min), new BigInteger(max));
    }

    [TestMethod]
    [DataRow(15, 16, 64)]
    [DataRow(65, 16, 64)]
    public void Between_Invalid(int value, int min, int max)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (sbyte)value, (sbyte)min, (sbyte)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (byte)value, (byte)min, (byte)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (short)value, (short)min, (short)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (ushort)value, (ushort)min, (ushort)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (int)value, (int)min, (int)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (uint)value, (uint)min, (uint)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (long)value, (long)min, (long)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (ulong)value, (ulong)min, (ulong)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (IntPtr)value, (IntPtr)min, (IntPtr)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (UIntPtr)value, (UIntPtr)min, (UIntPtr)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (Int128)value, (Int128)min, (Int128)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), (UInt128)value, (UInt128)min, (UInt128)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.Between(nameof(value), new BigInteger(value), new BigInteger(min), new BigInteger(max)));
    }

    [TestMethod]
    [DataRow(1, 0)]
    [DataRow(16, 15)]
    public void GreaterThan_Valid(int value, int min)
    {
        Validation.GreaterThan(nameof(value), (sbyte)value, (sbyte)min);
        Validation.GreaterThan(nameof(value), (byte)value, (byte)min);
        Validation.GreaterThan(nameof(value), (short)value, (short)min);
        Validation.GreaterThan(nameof(value), (ushort)value, (ushort)min);
        Validation.GreaterThan(nameof(value), (int)value, (int)min);
        Validation.GreaterThan(nameof(value), (uint)value, (uint)min);
        Validation.GreaterThan(nameof(value), (long)value, (long)min);
        Validation.GreaterThan(nameof(value), (ulong)value, (ulong)min);
        Validation.GreaterThan(nameof(value), (IntPtr)value, (IntPtr)min);
        Validation.GreaterThan(nameof(value), (UIntPtr)value, (UIntPtr)min);
        Validation.GreaterThan(nameof(value), (Int128)value, (Int128)min);
        Validation.GreaterThan(nameof(value), (UInt128)value, (UInt128)min);
        Validation.GreaterThan(nameof(value), new BigInteger(value), new BigInteger(min));
    }

    [TestMethod]
    [DataRow(0, 0)]
    [DataRow(15, 16)]
    [DataRow(16, 16)]
    public void GreaterThan_Invalid(int value, int min)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (sbyte)value, (sbyte)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (byte)value, (byte)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (short)value, (short)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (ushort)value, (ushort)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (int)value, (int)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (uint)value, (uint)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (long)value, (long)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (ulong)value, (ulong)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (IntPtr)value, (IntPtr)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (UIntPtr)value, (UIntPtr)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (Int128)value, (Int128)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), (UInt128)value, (UInt128)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThan(nameof(value), new BigInteger(value), new BigInteger(min)));
    }

    [TestMethod]
    [DataRow(1, 0)]
    [DataRow(0, 0)]
    [DataRow(16, 15)]
    [DataRow(16, 16)]
    public void GreaterThanOrEqualTo_Valid(int value, int min)
    {
        Validation.GreaterThanOrEqualTo(nameof(value), (sbyte)value, (sbyte)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (byte)value, (byte)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (short)value, (short)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (ushort)value, (ushort)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (int)value, (int)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (uint)value, (uint)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (long)value, (long)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (ulong)value, (ulong)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (IntPtr)value, (IntPtr)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (UIntPtr)value, (UIntPtr)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (Int128)value, (Int128)min);
        Validation.GreaterThanOrEqualTo(nameof(value), (UInt128)value, (UInt128)min);
        Validation.GreaterThanOrEqualTo(nameof(value), new BigInteger(value), new BigInteger(min));
    }

    [TestMethod]
    [DataRow(0, 1)]
    [DataRow(12, 16)]
    public void GreaterThanOrEqualTo_Invalid(int value, int min)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (sbyte)value, (sbyte)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (byte)value, (byte)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (short)value, (short)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (ushort)value, (ushort)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (int)value, (int)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (uint)value, (uint)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (long)value, (long)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (ulong)value, (ulong)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (IntPtr)value, (IntPtr)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (UIntPtr)value, (UIntPtr)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (Int128)value, (Int128)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), (UInt128)value, (UInt128)min));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.GreaterThanOrEqualTo(nameof(value), new BigInteger(value), new BigInteger(min)));
    }

    [TestMethod]
    [DataRow(0, 1)]
    [DataRow(15, 16)]
    public void LessThan_Valid(int value, int max)
    {
        Validation.LessThan(nameof(value), (sbyte)value, (sbyte)max);
        Validation.LessThan(nameof(value), (byte)value, (byte)max);
        Validation.LessThan(nameof(value), (short)value, (short)max);
        Validation.LessThan(nameof(value), (ushort)value, (ushort)max);
        Validation.LessThan(nameof(value), (int)value, (int)max);
        Validation.LessThan(nameof(value), (uint)value, (uint)max);
        Validation.LessThan(nameof(value), (long)value, (long)max);
        Validation.LessThan(nameof(value), (ulong)value, (ulong)max);
        Validation.LessThan(nameof(value), (IntPtr)value, (IntPtr)max);
        Validation.LessThan(nameof(value), (UIntPtr)value, (UIntPtr)max);
        Validation.LessThan(nameof(value), (Int128)value, (Int128)max);
        Validation.LessThan(nameof(value), (UInt128)value, (UInt128)max);
        Validation.LessThan(nameof(value), new BigInteger(value), new BigInteger(max));
    }

    [TestMethod]
    [DataRow(0, 0)]
    [DataRow(16, 16)]
    [DataRow(17, 16)]
    public void LessThan_Invalid(int value, int max)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (sbyte)value, (sbyte)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (byte)value, (byte)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (short)value, (short)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (ushort)value, (ushort)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (int)value, (int)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (uint)value, (uint)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (long)value, (long)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (ulong)value, (ulong)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (IntPtr)value, (IntPtr)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (UIntPtr)value, (UIntPtr)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (Int128)value, (Int128)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), (UInt128)value, (UInt128)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThan(nameof(value), new BigInteger(value), new BigInteger(max)));
    }

    [TestMethod]
    [DataRow(0, 1)]
    [DataRow(1, 1)]
    [DataRow(15, 16)]
    [DataRow(16, 16)]
    public void LessThanOrEqualTo_Valid(int value, int max)
    {
        Validation.LessThanOrEqualTo(nameof(value), (sbyte)value, (sbyte)max);
        Validation.LessThanOrEqualTo(nameof(value), (byte)value, (byte)max);
        Validation.LessThanOrEqualTo(nameof(value), (short)value, (short)max);
        Validation.LessThanOrEqualTo(nameof(value), (ushort)value, (ushort)max);
        Validation.LessThanOrEqualTo(nameof(value), (int)value, (int)max);
        Validation.LessThanOrEqualTo(nameof(value), (uint)value, (uint)max);
        Validation.LessThanOrEqualTo(nameof(value), (long)value, (long)max);
        Validation.LessThanOrEqualTo(nameof(value), (ulong)value, (ulong)max);
        Validation.LessThanOrEqualTo(nameof(value), (IntPtr)value, (IntPtr)max);
        Validation.LessThanOrEqualTo(nameof(value), (UIntPtr)value, (UIntPtr)max);
        Validation.LessThanOrEqualTo(nameof(value), (Int128)value, (Int128)max);
        Validation.LessThanOrEqualTo(nameof(value), (UInt128)value, (UInt128)max);
        Validation.LessThanOrEqualTo(nameof(value), new BigInteger(value), new BigInteger(max));
    }

    [TestMethod]
    [DataRow(2, 1)]
    [DataRow(17, 16)]
    public void LessThanOrEqualTo_Invalid(int value, int max)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (sbyte)value, (sbyte)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (byte)value, (byte)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (short)value, (short)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (ushort)value, (ushort)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (int)value, (int)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (uint)value, (uint)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (long)value, (long)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (ulong)value, (ulong)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (IntPtr)value, (IntPtr)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (UIntPtr)value, (UIntPtr)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (Int128)value, (Int128)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), (UInt128)value, (UInt128)max));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.LessThanOrEqualTo(nameof(value), new BigInteger(value), new BigInteger(max)));
    }

    [TestMethod]
    [DataRow(2, 2)]
    [DataRow(9, 3)]
    [DataRow(28, 7)]
    [DataRow(32, 16)]
    public void MultipleOf_Valid(int value, int multipleOf)
    {
        Validation.MultipleOf(nameof(value), (sbyte)value, (sbyte)multipleOf);
        Validation.MultipleOf(nameof(value), (byte)value, (byte)multipleOf);
        Validation.MultipleOf(nameof(value), (short)value, (short)multipleOf);
        Validation.MultipleOf(nameof(value), (ushort)value, (ushort)multipleOf);
        Validation.MultipleOf(nameof(value), (int)value, (int)multipleOf);
        Validation.MultipleOf(nameof(value), (uint)value, (uint)multipleOf);
        Validation.MultipleOf(nameof(value), (long)value, (long)multipleOf);
        Validation.MultipleOf(nameof(value), (ulong)value, (ulong)multipleOf);
        Validation.MultipleOf(nameof(value), (IntPtr)value, (IntPtr)multipleOf);
        Validation.MultipleOf(nameof(value), (UIntPtr)value, (UIntPtr)multipleOf);
        Validation.MultipleOf(nameof(value), (Int128)value, (Int128)multipleOf);
        Validation.MultipleOf(nameof(value), (UInt128)value, (UInt128)multipleOf);
        Validation.MultipleOf(nameof(value), new BigInteger(value), new BigInteger(multipleOf));
    }

    [TestMethod]
    [DataRow(0, 2)]
    [DataRow(31, 16)]
    [DataRow(33, 16)]
    public void MultipleOf_Invalid(int value, int multipleOf)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (sbyte)value, (sbyte)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (byte)value, (byte)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (short)value, (short)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (ushort)value, (ushort)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (int)value, (int)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (uint)value, (uint)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (long)value, (long)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (ulong)value, (ulong)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (IntPtr)value, (IntPtr)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (UIntPtr)value, (UIntPtr)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (Int128)value, (Int128)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), (UInt128)value, (UInt128)multipleOf));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.MultipleOf(nameof(value), new BigInteger(value), new BigInteger(multipleOf)));
    }

    [TestMethod]
    [DataRow(1)]
    [DataRow(32)]
    public void NotEmpty_Valid(int size)
    {
        Validation.NotEmpty(nameof(size), (sbyte)size);
        Validation.NotEmpty(nameof(size), (byte)size);
        Validation.NotEmpty(nameof(size), (short)size);
        Validation.NotEmpty(nameof(size), (ushort)size);
        Validation.NotEmpty(nameof(size), (int)size);
        Validation.NotEmpty(nameof(size), (uint)size);
        Validation.NotEmpty(nameof(size), (long)size);
        Validation.NotEmpty(nameof(size), (ulong)size);
        Validation.NotEmpty(nameof(size), (IntPtr)size);
        Validation.NotEmpty(nameof(size), (UIntPtr)size);
        Validation.NotEmpty(nameof(size), (Int128)size);
        Validation.NotEmpty(nameof(size), (UInt128)size);
        Validation.NotEmpty(nameof(size), new BigInteger(size));
    }

    [TestMethod]
    [DataRow(0)]
    public void NotEmpty_Invalid(int size)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (sbyte)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (byte)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (short)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (ushort)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (int)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (uint)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (long)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (ulong)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (IntPtr)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (UIntPtr)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (Int128)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), (UInt128)size));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotEmpty(nameof(size), new BigInteger(size)));
    }

    [TestMethod]
    public void NotNull_Valid()
    {
        var aString = string.Empty;
        var strings = Array.Empty<string>();
        var bytes = Array.Empty<byte>();
        var chars = Array.Empty<char>();
        var ints = Array.Empty<int>();
        var twoDimensionalArray = Array.Empty<int[,]>();
        var jaggedArray = Array.Empty<byte[]>();
        var list = new List<byte>();
        var dictionary = new Dictionary<string, string>();
        var tuple = (' ', ' ');
        DateTime? dateTime = DateTime.Now;
        Encodings.Base64Variant? nullableEnum = Encodings.Base64Variant.Original;
        bool? boolean = false;
        int? integer = 0;
        object anObject = 0;
        dynamic dynamic = 0;

        Validation.NotNull(nameof(aString), aString);
        Validation.NotNull(nameof(strings), strings);
        Validation.NotNull(nameof(bytes), bytes);
        Validation.NotNull(nameof(chars), chars);
        Validation.NotNull(nameof(ints), ints);
        Validation.NotNull(nameof(twoDimensionalArray), twoDimensionalArray);
        Validation.NotNull(nameof(jaggedArray), jaggedArray);
        Validation.NotNull(nameof(list), list);
        Validation.NotNull(nameof(dictionary), dictionary);
        Validation.NotNull(nameof(tuple), tuple.Item1);
        Validation.NotNull(nameof(dateTime), dateTime);
        Validation.NotNull(nameof(nullableEnum), nullableEnum);
        Validation.NotNull(nameof(boolean), boolean);
        Validation.NotNull(nameof(integer), integer);
        Validation.NotNull(nameof(anObject), anObject);
        Validation.NotNull(nameof(dynamic), dynamic);
    }

    [TestMethod]
    public void NotNull_Invalid()
    {
        string aString = null;
        string? nullableString = null;
        byte[] array = null;
        char[]? nullableArray = null;
        int[,] twoDimensionalArray = null;
        byte[][] jaggedArray = null;
        List<string> collection = null;
        List<string>? nullableCollection = null;
        int? nullableValue = null;
        (byte[], char) tuple = (null, ' ');
        (bool?, bool?) tupleWithNullables = (false, null);
        (string, string)? nullableTuple = null;
        DateTime? nullableStruct = null;
        Encodings.Base64Variant? nullableEnum = null;
        object anObject = null;
        // Not possible to do dynamic
        IDisposable anInterface = null;
        Action aDelegate = null;

        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(aString), aString));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(nullableString), nullableString));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(array), array));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(nullableArray), nullableArray));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(twoDimensionalArray), twoDimensionalArray));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(jaggedArray), jaggedArray));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(collection), collection));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(nullableCollection), nullableCollection));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(nullableValue), nullableValue));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(tuple), tuple.Item1));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(tupleWithNullables), tupleWithNullables.Item2));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(nullableTuple), nullableTuple));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(nullableStruct), nullableStruct));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(nullableEnum), nullableEnum));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(anObject), anObject));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(anInterface), anInterface));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNull(nameof(aDelegate), aDelegate));
    }

    [TestMethod]
    public void NotNullOrEmpty_Valid()
    {
        var aString = "test";
        string? nullableString = "test";
        string[] array = ["test"];
        char[]? nullableArray = ['a'];
        byte[][] jaggedArray = [ [0x00] ];
        List<byte> collection = [0x00];
        List<string>? nullableCollection = ["test"];
        var tuple = (" ", " ");
        dynamic aDynamic = "test";

        Validation.NotNullOrEmpty(nameof(aString), aString);
        Validation.NotNullOrEmpty(nameof(nullableString), nullableString);
        Validation.NotNullOrEmpty(nameof(array), array);
        Validation.NotNullOrEmpty(nameof(nullableArray), nullableArray);
        Validation.NotNullOrEmpty(nameof(jaggedArray), jaggedArray);
        Validation.NotNullOrEmpty(nameof(collection), collection);
        Validation.NotNullOrEmpty(nameof(nullableCollection), nullableCollection);
        Validation.NotNullOrEmpty(nameof(tuple), tuple.Item1);
        Validation.NotNullOrEmpty(nameof(aDynamic), aDynamic);
    }

    [TestMethod]
    public void NotNullOrEmpty_Invalid()
    {
        string nullString = null;
        var emptyString = string.Empty;
        string[] nullArray = null;
        string[] emptyArray = [];
        List<string> nullCollection = null;
        List<string> emptyCollection = [];
        byte[][] nullJaggedArray = null;
        byte[][] emptyJaggedArray = [];

        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNullOrEmpty(nameof(nullString), nullString));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotNullOrEmpty(nameof(emptyString), emptyString));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNullOrEmpty(nameof(nullArray), nullArray));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotNullOrEmpty(nameof(emptyArray), emptyArray));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNullOrEmpty(nameof(nullCollection), nullCollection));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotNullOrEmpty(nameof(emptyCollection), emptyCollection));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.NotNullOrEmpty(nameof(nullJaggedArray), nullJaggedArray));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.NotNullOrEmpty(nameof(emptyJaggedArray), emptyJaggedArray));
    }

    [TestMethod]
    public void HasNoNullValues_Valid()
    {
        string[] array = ["test"];
        List<string> collection = ["test"];
        int?[] nullableArray = [1, 2];
        List<string?> nullableCollection = ["test"];

        Validation.HasNoNullValues(nameof(array), array);
        Validation.HasNoNullValues(nameof(collection), collection);
        Validation.HasNoNullValues(nameof(nullableArray), nullableArray);
        Validation.HasNoNullValues(nameof(nullableCollection), nullableCollection);
    }

    [TestMethod]
    public void HasNoNullValues_Invalid()
    {
        string[] nullArray = null;
        List<string> nullCollection = null;
        int?[] nullElement = [null];
        object[] nullElements = ["test", null];

        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.HasNoNullValues(nameof(nullArray), nullArray));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.HasNoNullValues(nameof(nullCollection), nullCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullElement), nullElement));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullElements), nullElements));
    }

    [TestMethod]
    public void HasNoNullOrEmptyValues_Valid()
    {
        string[] array = ["test"];
        List<string> collection = ["test"];
        int?[] nullableArray = [1, 2];
        List<string?> nullableCollection = ["test"];

        Validation.HasNoNullOrEmptyValues(nameof(array), array);
        Validation.HasNoNullOrEmptyValues(nameof(collection), collection);
        Validation.HasNoNullOrEmptyValues(nameof(nullableArray), nullableArray);
        Validation.HasNoNullOrEmptyValues(nameof(nullableCollection), nullableCollection);
    }

    [TestMethod]
    public void HasNoNullOrEmptyValues_Invalid()
    {
        string nullString = null;
        var emptyString = string.Empty;
        string[] nullArray = null;
        List<string> nullCollection = null;
        string[] emptyArray = [];
        List<string> emptyCollection = [];
        int?[] nullArrayElement = [null];
        List<string> nullCollectionElement = [null];
        string[] emptyArrayElement = [""];
        List<string> emptyCollectionElement = [""];
        object[] nullArrayElements = ["test", null];
        List<string> nullCollectionElements = ["test", null];
        string[] emptyArrayElements = ["test", ""];
        List<string> emptyCollectionElements = ["test", ""];

        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullString), nullString));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyString), emptyString));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullArray), nullArray));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullCollection), nullCollection));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyArray), emptyArray));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyCollection), emptyCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullArrayElement), nullArrayElement));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullCollectionElement), nullCollectionElement));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyArrayElement), emptyArrayElement));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyCollectionElement), emptyCollectionElement));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullArrayElements), nullArrayElements));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullCollectionElements), nullCollectionElements));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyArrayElements), emptyArrayElements));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyCollectionElements), emptyCollectionElements));
    }

    [TestMethod]
    public void HasNoNullValues_Jagged_Valid()
    {
        string[][] emptyJaggedArray =
        [
            []
        ];
        List<string[]> emptyJaggedCollection =
        [
            []
        ];
        string[][] strings =
        [
            ["test1", "test2"]
        ];
        byte[][] bytes =
        [
            [0x00, 0x01],
            [0x02, 0x03]
        ];
        char[][] chars =
        [
            ['a', 'b']
        ];
        int?[][] ints =
        [
            [1, 2]
        ];
        bool?[][] bools =
        [
            [true]
        ];
        List<List<byte>> collection =
        [
            [0x00]
        ];

        Validation.HasNoNullValues(nameof(emptyJaggedArray), emptyJaggedArray);
        Validation.HasNoNullValues(nameof(emptyJaggedCollection), emptyJaggedCollection);
        Validation.HasNoNullValues(nameof(strings), strings);
        Validation.HasNoNullValues(nameof(bytes), bytes);
        Validation.HasNoNullValues(nameof(chars), chars);
        Validation.HasNoNullValues(nameof(ints), ints);
        Validation.HasNoNullValues(nameof(bools), bools);
        Validation.HasNoNullValues(nameof(collection), collection);
    }

    [TestMethod]
    public void HasNoNullValues_Jagged_Invalid()
    {
        string[][] nullJaggedArray = null;
        List<byte[]> nullJaggedCollection = null;
        string[][] nullArray =
        [
            null
        ];
        List<byte[]> nullCollection =
        [
            null
        ];
        string[][] nullSecondArray =
        [
            ["test"],
            null
        ];
        List<byte[]> nullSecondCollection =
        [
            [0x00],
            null
        ];
        string[][] nullValueInArray =
        [
            [null]
        ];
        List<byte?[]> nullValueInCollection =
        [
            [null]
        ];
        string[][] nullValuesInArray =
        [
            ["test", null]
        ];
        List<byte?[]> nullValuesInCollection =
        [
            [0x00, null]
        ];
        string[][] nullValuesInSecondArray =
        [
            ["test1", "test2"],
            [null, "test3"]
        ];
        List<byte?[]> nullValuesInSecondCollection =
        [
            [0x00, 0x01],
            [null, 0x02]
        ];

        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.HasNoNullValues(nameof(nullJaggedArray), nullJaggedArray));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.HasNoNullValues(nameof(nullJaggedCollection), nullJaggedCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullArray), nullArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullCollection), nullCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullSecondArray), nullSecondArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullSecondCollection), nullSecondCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullValueInArray), nullValueInArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullValueInCollection), nullValueInCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullValuesInArray), nullValuesInArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullValuesInCollection), nullValuesInCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullValuesInSecondArray), nullValuesInSecondArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullValues(nameof(nullValuesInSecondCollection), nullValuesInSecondCollection));
    }

    [TestMethod]
    public void HasNoNullOrEmptyValues_Jagged_Valid()
    {
        string[][] strings =
        [
            ["test1", "test2"]
        ];
        byte[][] bytes =
        [
            [0x00, 0x01],
            [0x02, 0x03]
        ];
        char[][] chars =
        [
            ['a', 'b']
        ];
        int?[][] ints =
        [
            [1, 2]
        ];
        bool?[][] bools =
        [
            [true]
        ];
        List<List<byte>> collection =
        [
            [0x00]
        ];

        Validation.HasNoNullOrEmptyValues(nameof(strings), strings);
        Validation.HasNoNullOrEmptyValues(nameof(bytes), bytes);
        Validation.HasNoNullOrEmptyValues(nameof(chars), chars);
        Validation.HasNoNullOrEmptyValues(nameof(ints), ints);
        Validation.HasNoNullOrEmptyValues(nameof(bools), bools);
        Validation.HasNoNullOrEmptyValues(nameof(collection), collection);
    }

    [TestMethod]
    public void HasNoNullOrEmptyValues_Jagged_Invalid()
    {
        string[][] nullJaggedArray = null;
        List<byte[]> nullJaggedCollection = null;
        string[][] emptyJaggedArray = [];
        List<byte[]> emptyJaggedCollection = [];
        string[][] nullArray =
        [
            null
        ];
        List<byte[]> nullCollection =
        [
            null
        ];
        string[][] emptyArray =
        [
            []
        ];
        List<byte[]> emptyCollection =
        [
            []
        ];
        string[][] nullSecondArray =
        [
            ["test"],
            null
        ];
        List<byte[]> nullSecondCollection =
        [
            [0x00],
            null
        ];
        string[][] emptySecondArray =
        [
            ["test"],
            []
        ];
        List<byte[]> emptySecondCollection =
        [
            [0x00],
            []
        ];
        string[][] nullValueInArray =
        [
            [null]
        ];
        List<byte?[]> nullValueInCollection =
        [
            [null]
        ];
        string[][] emptyValueInArray =
        [
            [""]
        ];
        List<string[]> emptyValueInCollection =
        [
            [""]
        ];
        string[][] nullValuesInArray =
        [
            ["test", null]
        ];
        List<string[]> nullValuesInCollection =
        [
            ["test", null]
        ];
        string[][] emptyValuesInArray =
        [
            ["test", ""]
        ];
        List<string[]> emptyValuesInCollection =
        [
            ["test", ""]
        ];
        string[][] nullValuesInSecondArray =
        [
            ["test1", "test2"],
            [null, "test3"]
        ];
        List<string[]> nullValuesInSecondCollection =
        [
            ["test1", "test2"],
            [null, "test3"]
        ];
        string[][] emptyValuesInSecondArray =
        [
            ["test1", "test2"],
            ["", "test3"]
        ];
        List<string[]> emptyValuesInSecondCollection =
        [
            ["test1", "test2"],
            ["", "test3"]
        ];

        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullJaggedArray), nullJaggedArray));
        Assert.ThrowsExactly<ArgumentNullException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullJaggedCollection), nullJaggedCollection));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyJaggedArray), emptyJaggedArray));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyJaggedCollection), emptyJaggedCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullArray), nullArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullCollection), nullCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyArray), emptyArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyCollection), emptyCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullSecondArray), nullSecondArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullSecondCollection), nullSecondCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptySecondArray), emptySecondArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptySecondCollection), emptySecondCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullValueInArray), nullValueInArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullValueInCollection), nullValueInCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyValueInArray), emptyValueInArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyValueInCollection), emptyValueInCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullValuesInArray), nullValuesInArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullValuesInCollection), nullValuesInCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyValuesInArray), emptyValuesInArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyValuesInCollection), emptyValuesInCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullValuesInSecondArray), nullValuesInSecondArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(nullValuesInSecondCollection), nullValuesInSecondCollection));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyValuesInSecondArray), emptyValuesInSecondArray));
        Assert.ThrowsExactly<ArgumentException>(() => Validation.HasNoNullOrEmptyValues(nameof(emptyValuesInSecondCollection), emptyValuesInSecondCollection));
    }
}
