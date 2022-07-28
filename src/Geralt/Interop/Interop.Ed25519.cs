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
        internal static extern unsafe int crypto_sign(byte* signedMessage, out long signedMessageLength, byte* message, long messageLength, byte* privateKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_open(byte* message, out long messageLength, byte* signedMessage, long signedMessageLength, byte* publicKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_detached(byte* signature, out long signatureLength, byte* message, long messageLength, byte* privateKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_sign_verify_detached(byte* signature, byte* message, long messageLength, byte* publicKey);
    }
}