using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class HChaCha20
{
    public const int OutputSize = crypto_core_hchacha20_OUTPUTBYTES;
    public const int KeySize = crypto_core_hchacha20_KEYBYTES;
    public const int NonceSize = crypto_core_hchacha20_INPUTBYTES;
    public const int PersonalizationSize = crypto_core_hchacha20_CONSTBYTES;

    public static void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> inputKeyingMaterial, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> personalization = default)
    {
        Validation.EqualTo(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, OutputSize);
        Validation.EqualTo(nameof(inputKeyingMaterial), inputKeyingMaterial.Length, KeySize);
        Validation.EqualTo(nameof(nonce), nonce.Length, NonceSize);
        if (personalization.Length != 0) {
            Validation.EqualTo(nameof(personalization), personalization.Length, PersonalizationSize);
            // https://link.springer.com/article/10.1007/s00145-018-9297-9
            if (ConstantTime.IsAllZeros(personalization)) { throw new ArgumentException($"{nameof(personalization)} cannot be all-zero.", nameof(personalization)); }
            if (ConstantTime.Equals(personalization[..8], personalization[8..])) { throw new ArgumentException($"{nameof(personalization)} must have asymmetry.", nameof(personalization)); }
        }
        Sodium.Initialize();
        int ret = crypto_core_hchacha20(outputKeyingMaterial, nonce, inputKeyingMaterial, personalization);
        if (ret != 0) { throw new CryptographicException("Error deriving key."); }
    }
}
