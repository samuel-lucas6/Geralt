using static Interop.Libsodium;

namespace Geralt;

public static class ConstantTime
{
    public static bool Equals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.NotEmpty(nameof(a), a.Length);
        Validation.NotEmpty(nameof(b), b.Length);
        Sodium.Initialize();
        // It's impossible to prevent the lengths being leaked
        if (a.Length != b.Length) { return false; }
        return sodium_memcmp(a, b, (nuint)a.Length) == 0;
    }

    public static void Increment(Span<byte> buffer)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Sodium.Initialize();
        sodium_increment(buffer, (nuint)buffer.Length);
    }

    public static void Add(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Validation.NotEmpty(nameof(a), a.Length);
        Validation.NotEmpty(nameof(b), b.Length);
        Validation.EqualToSize(nameof(a), a.Length, buffer.Length);
        Validation.EqualToSize(nameof(a), a.Length, b.Length);
        Sodium.Initialize();
        a.CopyTo(buffer);
        sodium_add(buffer, b, (nuint)buffer.Length);
    }

    public static void Subtract(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Validation.NotEmpty(nameof(a), a.Length);
        Validation.NotEmpty(nameof(b), b.Length);
        Validation.EqualToSize(nameof(a), a.Length, buffer.Length);
        Validation.EqualToSize(nameof(a), a.Length, b.Length);
        Sodium.Initialize();
        a.CopyTo(buffer);
        sodium_sub(buffer, b, (nuint)buffer.Length);
    }

    public static bool IsLessThan(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.NotEmpty(nameof(a), a.Length);
        Validation.NotEmpty(nameof(b), b.Length);
        Validation.EqualToSize(nameof(a), a.Length, b.Length);
        Sodium.Initialize();
        return sodium_compare(a, b, (nuint)a.Length) == -1;
    }

    public static bool IsGreaterThan(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.NotEmpty(nameof(a), a.Length);
        Validation.NotEmpty(nameof(b), b.Length);
        Validation.EqualToSize(nameof(a), a.Length, b.Length);
        Sodium.Initialize();
        return sodium_compare(a, b, (nuint)a.Length) == 1;
    }

    public static bool IsAllZeros(ReadOnlySpan<byte> buffer)
    {
        Sodium.Initialize();
        return sodium_is_zero(buffer, (nuint)buffer.Length) == 1;
    }
}
