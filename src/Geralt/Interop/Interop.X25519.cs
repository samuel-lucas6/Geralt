using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_kx_PUBLICKEYBYTES = 32;
        internal const int crypto_kx_SECRETKEYBYTES = 32;
        internal const int crypto_kx_SEEDBYTES = 32;
        internal const int crypto_kx_SESSIONKEYBYTES = 32;
        internal const int crypto_scalarmult_BYTES = 32;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_kx_keypair(byte* publicKey, byte* privateKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_kx_seed_keypair(byte* publicKey, byte* privateKey, byte* seed);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_scalarmult_base(byte* publicKey, byte* privateKey);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_scalarmult(byte* sharedSecret, byte* senderPrivateKey, byte* recipientPublicKey);
    }
}
