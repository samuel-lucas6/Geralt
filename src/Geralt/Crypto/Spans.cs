namespace Geralt;

public static class Spans
{
    public static Span<byte> Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        checked
        {
            var result = GC.AllocateArray<byte>(a.Length + b.Length, pinned: true);
            a.CopyTo(result);
            b.CopyTo(result.AsSpan(a.Length));
            return result.AsSpan();
        }
    }
    
    public static Span<byte> Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        checked
        {
            var result = GC.AllocateArray<byte>(a.Length + b.Length + c.Length, pinned: true);
            a.CopyTo(result);
            b.CopyTo(result.AsSpan(a.Length));
            c.CopyTo(result.AsSpan(a.Length + b.Length));
            return result.AsSpan();
        }
    }
    
    public static Span<byte> Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        checked
        {
            var result = GC.AllocateArray<byte>(a.Length + b.Length + c.Length + d.Length, pinned: true);
            a.CopyTo(result);
            b.CopyTo(result.AsSpan(a.Length));
            c.CopyTo(result.AsSpan(a.Length + b.Length));
            d.CopyTo(result.AsSpan(a.Length + b.Length + c.Length));
            return result.AsSpan();
        }
    }
    
    public static Span<byte> Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e)
    {
        checked
        {
            var result = GC.AllocateArray<byte>(a.Length + b.Length + c.Length + d.Length + e.Length, pinned: true);
            a.CopyTo(result);
            b.CopyTo(result.AsSpan(a.Length));
            c.CopyTo(result.AsSpan(a.Length + b.Length));
            d.CopyTo(result.AsSpan(a.Length + b.Length + c.Length));
            e.CopyTo(result.AsSpan(a.Length + b.Length + c.Length + d.Length));
            return result.AsSpan();
        }
    }
}