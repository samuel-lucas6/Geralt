using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_sign_ed25519ph_statebytes = 208;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519ph_init(ref crypto_sign_ed25519ph_state state);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519ph_update(ref crypto_sign_ed25519ph_state state, ReadOnlySpan<byte> message, ulong messageLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519ph_final_create(ref crypto_sign_ed25519ph_state state, Span<byte> signature, out ulong signatureLength, ReadOnlySpan<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519ph_final_verify(ref crypto_sign_ed25519ph_state state, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey);

        [StructLayout(LayoutKind.Explicit, Size = crypto_sign_ed25519ph_statebytes)]
        internal struct crypto_sign_ed25519ph_state;
    }
}
