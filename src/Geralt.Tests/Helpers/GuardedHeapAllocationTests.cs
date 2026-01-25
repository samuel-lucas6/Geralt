namespace Geralt.Tests;

[TestClass]
public class GuardedHeapAllocationTests
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
    public void GuardedHeapAllocation_Valid()
    {
        Span<byte> garbage = stackalloc byte[ChaCha20.KeySize];
        garbage.Fill(0xdb);
        Span<byte> copy = stackalloc byte[garbage.Length];

        using var secret = new GuardedHeapAllocation(garbage.Length);
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

        //secret.NoAccess();
        //RandomNumberGenerator.Fill(key);

        //secret.Dispose();
        //RandomNumberGenerator.Fill(key);
    }*/

    [TestMethod]
    [DynamicData(nameof(InvalidGuardedHeapAllocationSizes))]
    public void GuardedHeapAllocation_Invalid(int size)
    {
        // This is the only exception that can be tested
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new GuardedHeapAllocation(size));
    }

    [TestMethod]
    public void GuardedHeapAllocation_Disposed()
    {
        var secret = new GuardedHeapAllocation(ChaCha20.KeySize);

        secret.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => secret.AsSpan());
        Assert.ThrowsExactly<ObjectDisposedException>(() => secret.NoAccess());
        Assert.ThrowsExactly<ObjectDisposedException>(() => secret.ReadOnly());
        Assert.ThrowsExactly<ObjectDisposedException>(() => secret.ReadWrite());
        secret.Dispose();
    }
}
