namespace Geralt;

public static class Spans
{
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        checked
        {
            Validation.EqualToSize(nameof(buffer), buffer.Length, a.Length + b.Length);
            Validation.NotEmpty(nameof(a), a.Length);
            Validation.NotEmpty(nameof(b), b.Length);
            Validation.EqualToSize(nameof(a), a.Length, buffer.Length - b.Length);
            Validation.EqualToSize(nameof(b), b.Length, buffer.Length - a.Length);
            for (int i = 0; i < a.Length; i++)
            {
                buffer[i] = a[i];
            }
            int index = 0;
            for (int i = a.Length; i < a.Length + b.Length; i++)
            {
                buffer[i] = b[index++];
            }
        }
    }

    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        checked
        {
            Validation.EqualToSize(nameof(buffer), buffer.Length, a.Length + b.Length + c.Length);
            Validation.NotEmpty(nameof(a), a.Length);
            Validation.NotEmpty(nameof(b), b.Length);
            Validation.NotEmpty(nameof(c), c.Length);
            Validation.EqualToSize(nameof(a), a.Length, buffer.Length - b.Length - c.Length);
            Validation.EqualToSize(nameof(b), b.Length, buffer.Length - a.Length - c.Length);
            Validation.EqualToSize(nameof(c), c.Length, buffer.Length - a.Length - b.Length);
            for (int i = 0; i < a.Length; i++)
            {
                buffer[i] = a[i];
            }
            int index = 0;
            for (int i = a.Length; i < a.Length + b.Length; i++)
            {
                buffer[i] = b[index++];
            }
            index = 0;
            for (int i = a.Length + b.Length; i < a.Length + b.Length + c.Length; i++)
            {
                buffer[i] = c[index++];
            }
        }
    }
    
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        checked
        {
            Validation.EqualToSize(nameof(buffer), buffer.Length, a.Length + b.Length + c.Length + d.Length);
            Validation.NotEmpty(nameof(a), a.Length);
            Validation.NotEmpty(nameof(b), b.Length);
            Validation.NotEmpty(nameof(c), c.Length);
            Validation.NotEmpty(nameof(d), d.Length);
            Validation.EqualToSize(nameof(a), a.Length, buffer.Length - b.Length - c.Length - d.Length);
            Validation.EqualToSize(nameof(b), b.Length, buffer.Length - a.Length - c.Length - d.Length);
            Validation.EqualToSize(nameof(c), c.Length, buffer.Length - a.Length - b.Length - d.Length);
            Validation.EqualToSize(nameof(d), d.Length, buffer.Length - a.Length - b.Length - c.Length);
            for (int i = 0; i < a.Length; i++)
            {
                buffer[i] = a[i];
            }
            int index = 0;
            for (int i = a.Length; i < a.Length + b.Length; i++)
            {
                buffer[i] = b[index++];
            }
            index = 0;
            for (int i = a.Length + b.Length; i < a.Length + b.Length + c.Length; i++)
            {
                buffer[i] = c[index++];
            }
            index = 0;
            for (int i = a.Length + b.Length + c.Length; i < a.Length + b.Length + c.Length + d.Length; i++)
            {
                buffer[i] = d[index++];
            }
        }
    }
    
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e)
    {
        checked
        {
            Validation.EqualToSize(nameof(buffer), buffer.Length, a.Length + b.Length + c.Length + d.Length + e.Length);
            Validation.NotEmpty(nameof(a), a.Length);
            Validation.NotEmpty(nameof(b), b.Length);
            Validation.NotEmpty(nameof(c), c.Length);
            Validation.NotEmpty(nameof(d), d.Length);
            Validation.NotEmpty(nameof(e), e.Length);
            Validation.EqualToSize(nameof(a), a.Length, buffer.Length - b.Length - c.Length - d.Length - e.Length);
            Validation.EqualToSize(nameof(b), b.Length, buffer.Length - a.Length - c.Length - d.Length - e.Length);
            Validation.EqualToSize(nameof(c), c.Length, buffer.Length - a.Length - b.Length - d.Length - e.Length);
            Validation.EqualToSize(nameof(d), d.Length, buffer.Length - a.Length - b.Length - c.Length - e.Length);
            Validation.EqualToSize(nameof(e), e.Length, buffer.Length - a.Length - b.Length - c.Length - d.Length);
            for (int i = 0; i < a.Length; i++)
            {
                buffer[i] = a[i];
            }
            int index = 0;
            for (int i = a.Length; i < a.Length + b.Length; i++)
            {
                buffer[i] = b[index++];
            }
            index = 0;
            for (int i = a.Length + b.Length; i < a.Length + b.Length + c.Length; i++)
            {
                buffer[i] = c[index++];
            }
            index = 0;
            for (int i = a.Length + b.Length + c.Length; i < a.Length + b.Length + c.Length + d.Length; i++)
            {
                buffer[i] = d[index++];
            }
            index = 0;
            for (int i = a.Length + b.Length + c.Length + d.Length; i < a.Length + b.Length + c.Length + d.Length + e.Length; i++)
            {
                buffer[i] = e[index++];
            }
        }
    }
    
    public static void Concat(Span<byte> buffer, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e, ReadOnlySpan<byte> f)
    {
        checked
        {
            Validation.EqualToSize(nameof(buffer), buffer.Length, a.Length + b.Length + c.Length + d.Length + e.Length + f.Length);
            Validation.NotEmpty(nameof(a), a.Length);
            Validation.NotEmpty(nameof(b), b.Length);
            Validation.NotEmpty(nameof(c), c.Length);
            Validation.NotEmpty(nameof(d), d.Length);
            Validation.NotEmpty(nameof(e), e.Length);
            Validation.NotEmpty(nameof(f), f.Length);
            Validation.EqualToSize(nameof(a), a.Length, buffer.Length - b.Length - c.Length - d.Length - e.Length - f.Length);
            Validation.EqualToSize(nameof(b), b.Length, buffer.Length - a.Length - c.Length - d.Length - e.Length - f.Length);
            Validation.EqualToSize(nameof(c), c.Length, buffer.Length - a.Length - b.Length - d.Length - e.Length - f.Length);
            Validation.EqualToSize(nameof(d), d.Length, buffer.Length - a.Length - b.Length - c.Length - e.Length - f.Length);
            Validation.EqualToSize(nameof(e), e.Length, buffer.Length - a.Length - b.Length - c.Length - d.Length - f.Length);
            Validation.EqualToSize(nameof(f), f.Length, buffer.Length - a.Length - b.Length - c.Length - d.Length - e.Length);
            for (int i = 0; i < a.Length; i++)
            {
                buffer[i] = a[i];
            }
            int index = 0;
            for (int i = a.Length; i < a.Length + b.Length; i++)
            {
                buffer[i] = b[index++];
            }
            index = 0;
            for (int i = a.Length + b.Length; i < a.Length + b.Length + c.Length; i++)
            {
                buffer[i] = c[index++];
            }
            index = 0;
            for (int i = a.Length + b.Length + c.Length; i < a.Length + b.Length + c.Length + d.Length; i++)
            {
                buffer[i] = d[index++];
            }
            index = 0;
            for (int i = a.Length + b.Length + c.Length + d.Length; i < a.Length + b.Length + c.Length + d.Length + e.Length; i++)
            {
                buffer[i] = e[index++];
            }
            index = 0;
            for (int i = a.Length + b.Length + c.Length + d.Length + e.Length; i < a.Length + b.Length + c.Length + d.Length + e.Length + f.Length; i++)
            {
                buffer[i] = f[index++];
            }
        }
    }
}