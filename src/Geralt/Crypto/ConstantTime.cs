using static Interop.Libsodium;

namespace Geralt;

public static class ConstantTime
{
    public static unsafe bool Equals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.NotEmpty(nameof(a), a.Length);
        Validation.NotEmpty(nameof(b), b.Length);
        Sodium.Initialize();
        // It's impossible to prevent the lengths being leaked
        if (a.Length != b.Length) { return false; }
        fixed (byte* aa = a, bb = b)
            return sodium_memcmp(aa, bb, (nuint)a.Length) == 0;
    }

    public static unsafe void Increment(Span<byte> buffer)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Sodium.Initialize();
        fixed (byte* b = buffer)
            sodium_increment(b, (nuint)buffer.Length);
    }

    public static unsafe void Add(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Validation.NotEmpty(nameof(a), a.Length);
        Validation.NotEmpty(nameof(b), b.Length);
        Validation.EqualToSize(nameof(a), a.Length, buffer.Length);
        Validation.EqualToSize(nameof(a), a.Length, b.Length);
        Sodium.Initialize();
        a.CopyTo(buffer);
        fixed (byte* aa = buffer, bb = b)
            sodium_add(aa, bb, (nuint)buffer.Length);
    }

    public static unsafe void Subtract(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Validation.NotEmpty(nameof(a), a.Length);
        Validation.NotEmpty(nameof(b), b.Length);
        Validation.EqualToSize(nameof(a), a.Length, buffer.Length);
        Validation.EqualToSize(nameof(a), a.Length, b.Length);
        Sodium.Initialize();
        a.CopyTo(buffer);
        fixed (byte* aa = buffer, bb = b)
            sodium_sub(aa, bb, (nuint)buffer.Length);
    }

    public static unsafe bool IsLessThan(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.NotEmpty(nameof(a), a.Length);
        Validation.NotEmpty(nameof(b), b.Length);
        Validation.EqualToSize(nameof(a), a.Length, b.Length);
        Sodium.Initialize();
        fixed (byte* aa = a, bb = b)
            return sodium_compare(aa, bb, (nuint)a.Length) == -1;
    }

    public static unsafe bool IsGreaterThan(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.NotEmpty(nameof(a), a.Length);
        Validation.NotEmpty(nameof(b), b.Length);
        Validation.EqualToSize(nameof(a), a.Length, b.Length);
        Sodium.Initialize();
        fixed (byte* aa = a, bb = b)
            return sodium_compare(aa, bb, (nuint)a.Length) == 1;
    }

    public static unsafe bool IsAllZeros(ReadOnlySpan<byte> buffer)
    {
        Sodium.Initialize();
        fixed (byte* b = buffer)
            return sodium_is_zero(b, (nuint)buffer.Length) == 1;
    }
}
