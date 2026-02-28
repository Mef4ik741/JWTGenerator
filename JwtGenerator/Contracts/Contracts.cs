namespace JwtGenerator.Contracts;

public sealed record GenerateTokenRequest(
    string Subject,
    string? Algorithm,
    int? LifetimeMinutes,
    IReadOnlyDictionary<string, string>? Claims);

public sealed record GenerateTokenResponse(
    string Token,
    string Algorithm,
    string KeyId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);

public sealed record ValidateTokenRequest(
    string Token,
    bool ValidateLifetime = true,
    bool ValidateIssuerAudience = true);

public sealed record ValidateTokenResponse(
    bool IsValid,
    string? Error,
    string? Algorithm,
    string? KeyId,
    IReadOnlyDictionary<string, object>? Payload);

public sealed record OpenIdConfigurationResponse(
    string Issuer,
    string JwksUri,
    string TokenEndpoint,
    IReadOnlyCollection<string> SupportedSigningAlgs);

public sealed record JwksResponse(IReadOnlyCollection<JwkKey> Keys);

public sealed record JwkKey(
    string Kty,
    string Use,
    string Kid,
    string Alg,
    string? N,
    string? E,
    string? Crv,
    string? X,
    string? Y);
