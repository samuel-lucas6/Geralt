using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_sign_PUBLICKEYBYTES = 32;
        internal const int crypto_sign_SECRETKEYBYTES = 64;
        internal const int crypto_sign_SEEDBYTES = 32;
        internal const int crypto_sign_BYTES = 64;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_keypair(byte* publicKey, byte* privateKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_seed_keypair(byte* publicKey, byte* privateKey, byte* seed);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_ed25519_sk_to_pk(byte* publicKey, byte* privateKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_ed25519_pk_to_curve25519(byte* X25519PublicKey, byte* Ed25519PublicKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_ed25519_sk_to_curve25519(byte* X25519PrivateKey, byte* Ed25519PrivateKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_detached(byte* signature, out ulong signatureLength, byte* message, ulong messageLength, byte* privateKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_verify_detached(byte* signature, byte* message, ulong messageLength, byte* publicKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int crypto_sign_init(ref crypto_sign_state state);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_update(ref crypto_sign_state state, byte* message, ulong messageLength);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_final_create(ref crypto_sign_state state, byte* signature, out ulong signatureLength, byte* privateKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_final_verify(ref crypto_sign_state state, byte* signature, byte* publicKey);

        [StructLayout(LayoutKind.Explicit, Size = 208)]
        internal struct crypto_sign_state
        {
        }
    }
}
