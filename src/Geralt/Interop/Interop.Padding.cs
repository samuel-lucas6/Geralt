using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int sodium_pad(out nuint paddedBufferLength, byte* buffer, nuint unpaddedBufferLength, nuint blockSize, nuint maxBufferLength);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int sodium_unpad(out nuint unpaddedBufferLength, byte* paddedBuffer, nuint paddedBufferLength, nuint blockSize);
    }
}