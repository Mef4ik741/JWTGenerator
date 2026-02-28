using System.Collections.Concurrent;
using System.Security.Cryptography;
using JwtGenerator.Abstractions;
using JwtGenerator.Constants;
using JwtGenerator.Contracts;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JwtGenerator.Security;

public sealed class InMemoryKeyMaterialStore : IKeyMaterialStore
{
    private readonly JwtOptions _options;
    private readonly ILogger<InMemoryKeyMaterialStore> _logger;

    private readonly SemaphoreSlim _initLock = new(1, 1);
    private volatile bool _initialized;

    private volatile KeyEntry _rsaCurrent = KeyEntry.Empty;
    private volatile KeyEntry _ecdsaCurrent = KeyEntry.Empty;

    private readonly ConcurrentDictionary<string, SecurityKey> _allKeys = new(StringComparer.Ordinal);

    public InMemoryKeyMaterialStore(IOptions<JwtOptions> options, ILogger<InMemoryKeyMaterialStore> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task EnsureInitializedAsync(CancellationToken ct)
    {
        if (_initialized)
        {
            return;
        }

        await _initLock.WaitAsync(ct);
        try
        {
            if (_initialized)
            {
                return;
            }

            RotateInternal();
            _initialized = true;
        }
        finally
        {
            _initLock.Release();
        }
    }

    public async Task RotateAsync(CancellationToken ct)
    {
        await EnsureInitializedAsync(ct);
        RotateInternal();
    }

    public async Task<(string KeyId, string Algorithm, SecurityKey Key)> GetSigningKeyAsync(string algorithm, CancellationToken ct)
    {
        await EnsureInitializedAsync(ct);

        var alg = NormalizeAlg(algorithm);
        return alg switch
        {
            JwtAlgorithms.RS256 => (_rsaCurrent.Kid, JwtAlgorithms.RS256, _rsaCurrent.Key),
            JwtAlgorithms.ES256 => (_ecdsaCurrent.Kid, JwtAlgorithms.ES256, _ecdsaCurrent.Key),
            JwtAlgorithms.HS256 => ("hmac", JwtAlgorithms.HS256, CreateHmacKey(_options.HmacSecret)),
            _ => throw new InvalidOperationException($"Unsupported algorithm '{algorithm}'")
        };
    }

    public async Task<SecurityKey?> TryResolveValidationKeyAsync(string? kid, string algorithm, CancellationToken ct)
    {
        await EnsureInitializedAsync(ct);

        var alg = NormalizeAlg(algorithm);
        if (alg == JwtAlgorithms.HS256)
        {
            return CreateHmacKey(_options.HmacSecret);
        }

        if (!string.IsNullOrWhiteSpace(kid) && _allKeys.TryGetValue(kid, out var key))
        {
            return key;
        }

        return alg switch
        {
            JwtAlgorithms.RS256 => _rsaCurrent.Key,
            JwtAlgorithms.ES256 => _ecdsaCurrent.Key,
            _ => null
        };
    }

    public async Task<JwksResponse> GetJwksAsync(CancellationToken ct)
    {
        await EnsureInitializedAsync(ct);

        var keys = new List<JwkKey>(capacity: 2)
        {
            BuildRsaJwk(_rsaCurrent),
            BuildEcdsaJwk(_ecdsaCurrent)
        };

        return new JwksResponse(keys);
    }

    private void RotateInternal()
    {
        var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa);
        var rsaKid = "rsa-" + Base64Url.Encode(Base64Url.RandomBytes(16));
        rsaKey.KeyId = rsaKid;

        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa);
        var ecdsaKid = "ec-" + Base64Url.Encode(Base64Url.RandomBytes(16));
        ecdsaKey.KeyId = ecdsaKid;

        _rsaCurrent = new KeyEntry(rsaKid, rsaKey);
        _ecdsaCurrent = new KeyEntry(ecdsaKid, ecdsaKey);

        _allKeys[rsaKid] = rsaKey;
        _allKeys[ecdsaKid] = ecdsaKey;

        _logger.LogInformation("Rotated signing keys. RSA kid={RsaKid}, ECDSA kid={EcdsaKid}", rsaKid, ecdsaKid);
    }

    private static SymmetricSecurityKey CreateHmacKey(string secret)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(secret);
        return new SymmetricSecurityKey(bytes) { KeyId = "hmac" };
    }

    private static string NormalizeAlg(string? algorithm)
    {
        if (string.IsNullOrWhiteSpace(algorithm))
        {
            return JwtAlgorithms.RS256;
        }

        return algorithm.Trim().ToUpperInvariant();
    }

    private static JwkKey BuildRsaJwk(KeyEntry entry)
    {
        var rsaKey = (RsaSecurityKey)entry.Key;
        var rsa = rsaKey.Rsa ?? RSA.Create(rsaKey.Parameters);
        var p = rsa.ExportParameters(includePrivateParameters: false);

        return new JwkKey(
            Kty: "RSA",
            Use: "sig",
            Kid: entry.Kid,
            Alg: JwtAlgorithms.RS256,
            N: p.Modulus is null ? null : Base64Url.Encode(p.Modulus),
            E: p.Exponent is null ? null : Base64Url.Encode(p.Exponent),
            Crv: null,
            X: null,
            Y: null);
    }

    private static JwkKey BuildEcdsaJwk(KeyEntry entry)
    {
        var ecKey = (ECDsaSecurityKey)entry.Key;
        var ec = ecKey.ECDsa ?? throw new InvalidOperationException("ECDSA key material is not available");
        var p = ec.ExportParameters(includePrivateParameters: false);

        return new JwkKey(
            Kty: "EC",
            Use: "sig",
            Kid: entry.Kid,
            Alg: JwtAlgorithms.ES256,
            N: null,
            E: null,
            Crv: "P-256",
            X: p.Q.X is null ? null : Base64Url.Encode(p.Q.X),
            Y: p.Q.Y is null ? null : Base64Url.Encode(p.Q.Y));
    }

    private sealed record KeyEntry(string Kid, SecurityKey Key)
    {
        public static KeyEntry Empty { get; } = new(string.Empty, new SymmetricSecurityKey(new byte[] { 0x00 }));
    }
}
