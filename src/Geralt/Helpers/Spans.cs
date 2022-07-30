namespace Geralt;

public static class Spans
{
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        a.CopyTo(buffer.Slice(start: 0, a.Length));
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        a.CopyTo(buffer.Slice(start: 0, a.Length));
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
    }
    
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        a.CopyTo(buffer.Slice(start: 0, a.Length));
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
        d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
    }
    
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e)
    {
        a.CopyTo(buffer.Slice(start: 0, a.Length));
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
        d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
        e.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length, e.Length));
    }
    
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e, ReadOnlySpan<byte> f)
    {
        a.CopyTo(buffer.Slice(start: 0, a.Length));
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
        d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
        e.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length, e.Length));
        f.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length + e.Length, f.Length));
    }
}