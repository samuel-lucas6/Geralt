namespace Geralt.Tests;

[TestClass]
public class SecureMemoryTests
{
    public static IEnumerable<object[]> InvalidLockMemorySizes()
    {
        yield return [0];
        yield return [SecureMemory.PageSize + 1];
        yield return [SecureMemory.PageSize - 1];
        yield return [SecureMemory.PageSize * 2 + 1];
        yield return [SecureMemory.PageSize * 2 - 1];
    }

    // With DataRow(), the associated test fails on macOS
    public static IEnumerable<object[]> InvalidGuardedHeapAllocationSizes()
    {
        yield return [0];
        yield return [SecureMemory.PageSize];
        yield return [GuardedHeapAllocation.MaxSize + 1];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(Environment.SystemPageSize, SecureMemory.PageSize);
        Assert.AreEqual(Environment.SystemPageSize - 16, GuardedHeapAllocation.MaxSize);
    }

    [TestMethod]
    public void ZeroMemory_Bytes_Valid()
    {
        Span<byte> b = stackalloc byte[ChaCha20.KeySize];
        RandomNumberGenerator.Fill(b);

        SecureMemory.ZeroMemory(b);

        Assert.IsTrue(b.SequenceEqual(new byte[b.Length]));
    }

    [TestMethod]
    public void ZeroMemory_Bytes_Invalid()
    {
        var b = Array.Empty<byte>();

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureMemory.ZeroMemory(b));
    }

    [TestMethod]
    public void ZeroMemory_Chars_Valid()
    {
        Span<char> b = stackalloc char[SecureRandom.MinStringLength];
        b.Fill('a');

        SecureMemory.ZeroMemory(b);

        Assert.IsTrue(b.SequenceEqual(new char[b.Length]));
    }

    [TestMethod]
    public void ZeroMemory_Chars_Invalid()
    {
        var b = Array.Empty<char>();

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureMemory.ZeroMemory(b));
    }

    [TestMethod]
    public void ZeroMemory_String_Valid()
    {
        ReadOnlySpan<char> s = RandomNumberGenerator.GetString(SecureRandom.AlphanumericSymbolChars, SecureRandom.MinStringLength).AsSpan();

        SecureMemory.ZeroMemory(s);

        Assert.IsTrue(s.SequenceEqual(new char[s.Length]));
        // Not the same as null or string.Empty
        Assert.IsTrue(s.ToString().All(c => c == '\0'));
    }

    [TestMethod]
    public void ZeroMemory_String_Invalid()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureMemory.ZeroMemory(string.Empty.AsSpan()));
    }

    [TestMethod]
    public void LockMemory_UnlockAndZeroMemory_Valid()
    {
        Span<byte> b = stackalloc byte[SecureMemory.PageSize];
        Span<byte> c = stackalloc byte[b.Length];
        RandomNumberGenerator.Fill(b);
        b.CopyTo(c);

        SecureMemory.LockMemory(b);

        Assert.IsTrue(b.SequenceEqual(c));

        SecureMemory.UnlockAndZeroMemory(b);

        Assert.IsTrue(b.SequenceEqual(new byte[b.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidLockMemorySizes), DynamicDataSourceType.Method)]
    public void LockMemory_UnlockAndZeroMemory_Invalid(int bufferSize)
    {
        var b = new byte[bufferSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureMemory.LockMemory(b));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureMemory.UnlockAndZeroMemory(b));
    }

    [TestMethod]
    public void LockMemory_UnlockAndZeroMemory_InvalidOperation()
    {
        var b = new byte[SecureMemory.PageSize * 65536];

        // This test fails on macOS - it apparently allows large amounts of memory to be locked
        if (!OperatingSystem.IsMacOS()) {
            Assert.ThrowsException<OutOfMemoryException>(() => SecureMemory.LockMemory(b));
        }
        // This test fails on Linux/macOS - munlock() must not return an error despite no locking taking place
        if (OperatingSystem.IsWindows()) {
            Assert.ThrowsException<InvalidOperationException>(() => SecureMemory.UnlockAndZeroMemory(b));
        }
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
        Assert.ThrowsException<ObjectDisposedException>(() => secret.Dispose());
    }
}
