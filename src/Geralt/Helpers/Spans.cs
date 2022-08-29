namespace Geralt;

public static class Spans
{
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        checked
        {
            Validation.EqualToSize(nameof(buffer), buffer.Length, a.Length + b.Length);
            Validation.EqualToSize(nameof(a), a.Length, buffer.Length - b.Length);
            Validation.EqualToSize(nameof(b), b.Length, buffer.Length - a.Length);
            a.CopyTo(buffer.Slice(start: 0, a.Length));
            b.CopyTo(buffer.Slice(start: a.Length, b.Length));
        }
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        checked
        {
            Validation.EqualToSize(nameof(buffer), buffer.Length, a.Length + b.Length + c.Length);
            Validation.EqualToSize(nameof(a), a.Length, buffer.Length - b.Length - c.Length);
            Validation.EqualToSize(nameof(b), b.Length, buffer.Length - a.Length - c.Length);
            Validation.EqualToSize(nameof(c), c.Length, buffer.Length - a.Length - b.Length);
            a.CopyTo(buffer.Slice(start: 0, a.Length));
            b.CopyTo(buffer.Slice(start: a.Length, b.Length));
            c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
        }
    }
    
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        checked
        {
            Validation.EqualToSize(nameof(buffer), buffer.Length, a.Length + b.Length + c.Length + d.Length);
            Validation.EqualToSize(nameof(a), a.Length, buffer.Length - b.Length - c.Length - d.Length);
            Validation.EqualToSize(nameof(b), b.Length, buffer.Length - a.Length - c.Length - d.Length);
            Validation.EqualToSize(nameof(c), c.Length, buffer.Length - a.Length - b.Length - d.Length);
            Validation.EqualToSize(nameof(d), d.Length, buffer.Length - a.Length - b.Length - c.Length);
            a.CopyTo(buffer.Slice(start: 0, a.Length));
            b.CopyTo(buffer.Slice(start: a.Length, b.Length));
            c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
            d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
        }
    }
    
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e)
    {
        checked
        {
            Validation.EqualToSize(nameof(buffer), buffer.Length, a.Length + b.Length + c.Length + d.Length + e.Length);
            Validation.EqualToSize(nameof(a), a.Length, buffer.Length - b.Length - c.Length - d.Length - e.Length);
            Validation.EqualToSize(nameof(b), b.Length, buffer.Length - a.Length - c.Length - d.Length - e.Length);
            Validation.EqualToSize(nameof(c), c.Length, buffer.Length - a.Length - b.Length - d.Length - e.Length);
            Validation.EqualToSize(nameof(d), d.Length, buffer.Length - a.Length - b.Length - c.Length - e.Length);
            Validation.EqualToSize(nameof(e), e.Length, buffer.Length - a.Length - b.Length - c.Length - d.Length);
            a.CopyTo(buffer.Slice(start: 0, a.Length));
            b.CopyTo(buffer.Slice(start: a.Length, b.Length));
            c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
            d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
            e.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length, e.Length));
        }
    }
    
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e, ReadOnlySpan<byte> f)
    {
        checked
        {
            Validation.EqualToSize(nameof(buffer), buffer.Length, a.Length + b.Length + c.Length + d.Length + e.Length + f.Length);
            Validation.EqualToSize(nameof(a), a.Length, buffer.Length - b.Length - c.Length - d.Length - e.Length - f.Length);
            Validation.EqualToSize(nameof(b), b.Length, buffer.Length - a.Length - c.Length - d.Length - e.Length - f.Length);
            Validation.EqualToSize(nameof(c), c.Length, buffer.Length - a.Length - b.Length - d.Length - e.Length - f.Length);
            Validation.EqualToSize(nameof(d), d.Length, buffer.Length - a.Length - b.Length - c.Length - e.Length - f.Length);
            Validation.EqualToSize(nameof(e), e.Length, buffer.Length - a.Length - b.Length - c.Length - d.Length - f.Length);
            Validation.EqualToSize(nameof(f), f.Length, buffer.Length - a.Length - b.Length - c.Length - d.Length - e.Length);
            a.CopyTo(buffer.Slice(start: 0, a.Length));
            b.CopyTo(buffer.Slice(start: a.Length, b.Length));
            c.CopyTo(buffer.Slice(start: a.Length + b.Length, c.Length));
            d.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length, d.Length));
            e.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length, e.Length));
            f.CopyTo(buffer.Slice(start: a.Length + b.Length + c.Length + d.Length + e.Length, f.Length));
        }
    }
}