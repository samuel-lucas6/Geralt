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
        Validation.EqualTo($"{nameof(outputKeyingMaterial)}.{nameof(outputKeyingMaterial.Length)}", outputKeyingMaterial.Length, OutputSize);
        Validation.EqualTo($"{nameof(inputKeyingMaterial)}.{nameof(inputKeyingMaterial.Length)}", inputKeyingMaterial.Length, KeySize);
        Validation.EqualTo($"{nameof(nonce)}.{nameof(nonce.Length)}", nonce.Length, NonceSize);
        if (personalization.Length != 0) {
            Validation.EqualTo($"{nameof(personalization)}.{nameof(personalization.Length)}", personalization.Length, PersonalizationSize);
            // https://link.springer.com/article/10.1007/s00145-018-9297-9 - Section 3.1 Non-random Properties of F
            if (ConstantTime.Equals(personalization[..8], personalization[8..])) { throw new ArgumentException($"{nameof(personalization)} cannot be all-zero and must have asymmetry.", nameof(personalization)); }
        }
        Sodium.Initialize();
        int ret = crypto_core_hchacha20(outputKeyingMaterial, nonce, inputKeyingMaterial, personalization);
        if (ret != 0) { throw new CryptographicException("Error deriving key."); }
    }
}
