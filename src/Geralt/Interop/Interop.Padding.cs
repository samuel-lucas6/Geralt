using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int sodium_pad(out int paddedBufferLength, byte* buffer, int unpaddedBufferLength, int blockSize, int maxBufferLength);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int sodium_unpad(out int unpaddedBufferLength, byte* paddedBuffer, int paddedBufferLength, int blockSize);
    }
}