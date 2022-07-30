﻿using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_stream_xchacha20_KEYBYTES = 32;
        internal const int crypto_stream_xchacha20_NONCEBYTES = 24;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_stream_xchacha20_xor(byte* ciphertext, byte* plaintext, ulong plaintextLength, byte* nonce, byte* key);
    }
}