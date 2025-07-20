namespace Geralt;

public static class Spans
{
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.EqualToSize(nameof(buffer), buffer.Length, checked(a.Length + b.Length));
        a.CopyTo(buffer[..a.Length]);
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        Validation.EqualToSize(nameof(buffer), buffer.Length, checked(a.Length + b.Length + c.Length));
        a.CopyTo(buffer[..a.Length]);
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        Validation.EqualToSize(nameof(buffer), buffer.Length, checked(a.Length + b.Length + c.Length + d.Length));
        a.CopyTo(buffer[..a.Length]);
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
        d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e)
    {
        Validation.EqualToSize(nameof(buffer), buffer.Length, checked(a.Length + b.Length + c.Length + d.Length + e.Length));
        a.CopyTo(buffer[..a.Length]);
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
        d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
        e.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length, e.Length));
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e, ReadOnlySpan<byte> f)
    {
        Validation.EqualToSize(nameof(buffer), buffer.Length, checked(a.Length + b.Length + c.Length + d.Length + e.Length + f.Length));
        a.CopyTo(buffer[..a.Length]);
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
        d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
        e.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length, e.Length));
        f.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length + e.Length, f.Length));
    }
}
