namespace Geralt;

public static class Spans
{
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Validation.EqualTo($"{nameof(buffer)}.{nameof(buffer.Length)}", buffer.Length, checked(a.Length + b.Length));
        if (buffer.Overlaps(a) || buffer.Overlaps(b)) { throw new ArgumentException($"{nameof(buffer)} cannot overlap with the spans being copied.", nameof(buffer)); }
        a.CopyTo(buffer[..a.Length]);
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        Validation.EqualTo($"{nameof(buffer)}.{nameof(buffer.Length)}", buffer.Length, checked(a.Length + b.Length + c.Length));
        if (buffer.Overlaps(a) || buffer.Overlaps(b) || buffer.Overlaps(c)) { throw new ArgumentException($"{nameof(buffer)} cannot overlap with the spans being copied.", nameof(buffer)); }
        a.CopyTo(buffer[..a.Length]);
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        Validation.EqualTo($"{nameof(buffer)}.{nameof(buffer.Length)}", buffer.Length, checked(a.Length + b.Length + c.Length + d.Length));
        if (buffer.Overlaps(a) || buffer.Overlaps(b) || buffer.Overlaps(c) || buffer.Overlaps(d)) { throw new ArgumentException($"{nameof(buffer)} cannot overlap with the spans being copied.", nameof(buffer)); }
        a.CopyTo(buffer[..a.Length]);
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
        d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e)
    {
        Validation.EqualTo($"{nameof(buffer)}.{nameof(buffer.Length)}", buffer.Length, checked(a.Length + b.Length + c.Length + d.Length + e.Length));
        if (buffer.Overlaps(a) || buffer.Overlaps(b) || buffer.Overlaps(c) || buffer.Overlaps(d) || buffer.Overlaps(e)) { throw new ArgumentException($"{nameof(buffer)} cannot overlap with the spans being copied.", nameof(buffer)); }
        a.CopyTo(buffer[..a.Length]);
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
        d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
        e.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length, e.Length));
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e, ReadOnlySpan<byte> f)
    {
        Validation.EqualTo($"{nameof(buffer)}.{nameof(buffer.Length)}", buffer.Length, checked(a.Length + b.Length + c.Length + d.Length + e.Length + f.Length));
        if (buffer.Overlaps(a) || buffer.Overlaps(b) || buffer.Overlaps(c) || buffer.Overlaps(d) || buffer.Overlaps(e) || buffer.Overlaps(f)) { throw new ArgumentException($"{nameof(buffer)} cannot overlap with the spans being copied.", nameof(buffer)); }
        a.CopyTo(buffer[..a.Length]);
        b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
        d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
        e.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length, e.Length));
        f.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length + e.Length, f.Length));
    }
}
