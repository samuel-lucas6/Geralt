namespace Geralt.Tests;

[TestClass]
public class SecureMemoryTests
{
    // With DataRow(), the associated test fails on macOS
    public static IEnumerable<object[]> InvalidGuardedHeapAllocationSizes()
    {
        yield return [0];
        yield return [Environment.SystemPageSize];
        yield return [GuardedHeapAllocation.MaxSize + 1];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(Environment.SystemPageSize - 16, GuardedHeapAllocation.MaxSize);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(ChaCha20.KeySize)]
    public void ZeroMemory_Bytes_Valid(int bufferSize)
    {
        Span<byte> b = stackalloc byte[bufferSize];
        RandomNumberGenerator.Fill(b);

        SecureMemory.ZeroMemory(b);

        Assert.IsTrue(b.SequenceEqual(new byte[b.Length]));
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(SecureRandom.MinStringSize)]
    public void ZeroMemory_Chars_Valid(int bufferSize)
    {
        Span<char> b = stackalloc char[bufferSize];
        b.Fill('a');

        SecureMemory.ZeroMemory(b);

        Assert.IsTrue(b.SequenceEqual(new char[b.Length]));
    }

    [TestMethod]
    public void ZeroMemory_String_Valid()
    {
        ReadOnlySpan<char> s = RandomNumberGenerator.GetString(SecureRandom.AlphanumericSymbolChars, SecureRandom.MinStringSize).AsSpan();

        SecureMemory.ZeroMemory(s);

        Assert.IsTrue(s.SequenceEqual(new char[s.Length]));
        // Not the same as null or string.Empty
        Assert.IsTrue(s.ToString().All(c => c == '\0'));
    }

    [TestMethod]
    public void GuardedHeapAllocation_Valid()
    {
        int size = ChaCha20.KeySize;
        Span<byte> garbage = Enumerable.Repeat((byte)0xdb, size).ToArray();
        Span<byte> copy = stackalloc byte[size];

        using var secret = new GuardedHeapAllocation(size);
        Span<byte> key = secret.AsSpan();
        Assert.IsTrue(key.SequenceEqual(garbage));

        RandomNumberGenerator.Fill(key);
        Assert.IsFalse(key.SequenceEqual(garbage));

        key.CopyTo(copy);
        secret.ReadOnly();
        Assert.IsTrue(key.SequenceEqual(copy));

        secret.NoAccess();
        // Can't check the value

        secret.ReadWrite();
        RandomNumberGenerator.Fill(key);
        Assert.IsFalse(key.SequenceEqual(copy));
    }

    // This test has to be run manually, commenting out parts because there's no way to catch the access violation
    /*[TestMethod]
    public void GuardedHeapAllocation_Tampered()
    {
        var secret = new GuardedHeapAllocation(ChaCha20.KeySize);
        Span<byte> key = secret.AsSpan();

        secret.ReadOnly();
        RandomNumberGenerator.Fill(key);

        secret.NoAccess();
        RandomNumberGenerator.Fill(key);

        secret.Dispose();
        RandomNumberGenerator.Fill(key);
    }*/

    [TestMethod]
    [DynamicData(nameof(InvalidGuardedHeapAllocationSizes), DynamicDataSourceType.Method)]
    public void GuardedHeapAllocation_Invalid(int size)
    {
        // This is the only exception that can be tested
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new GuardedHeapAllocation(size));
    }

    [TestMethod]
    public void GuardedHeapAllocation_Disposed()
    {
        var secret = new GuardedHeapAllocation(ChaCha20.KeySize);

        secret.Dispose();

        Assert.ThrowsException<ObjectDisposedException>(() => secret.AsSpan());
        Assert.ThrowsException<ObjectDisposedException>(() => secret.NoAccess());
        Assert.ThrowsException<ObjectDisposedException>(() => secret.ReadOnly());
        Assert.ThrowsException<ObjectDisposedException>(() => secret.ReadWrite());
    }
}
