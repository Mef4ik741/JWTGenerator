using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JwtGenerator.Abstractions;
using JwtGenerator.Constants;
using JwtGenerator.Contracts;
using JwtGenerator.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JwtGenerator.Services;

public sealed class TokenService : ITokenService
{
    private readonly JwtOptions _options;
    private readonly IKeyMaterialStore _keys;
    private readonly ILogger<TokenService> _logger;

    public TokenService(IOptions<JwtOptions> options, IKeyMaterialStore keys, ILogger<TokenService> logger)
    {
        _options = options.Value;
        _keys = keys;
        _logger = logger;
    }

    public async Task<GenerateTokenResponse> GenerateAsync(GenerateTokenRequest request, CancellationToken ct)
    {
        var algorithm = string.IsNullOrWhiteSpace(request.Algorithm) ? _options.DefaultAlgorithm : request.Algorithm;
        algorithm = algorithm.Trim().ToUpperInvariant();

        var lifetimeMinutes = request.LifetimeMinutes ?? _options.TokenLifetimeMinutes;
        if (lifetimeMinutes <= 0)
        {
            lifetimeMinutes = _options.TokenLifetimeMinutes;
        }

        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(lifetimeMinutes);

        var (kid, alg, key) = await _keys.GetSigningKeyAsync(algorithm, ct);

        var creds = new SigningCredentials(key, MapSigningAlgorithm(alg));

        var claims = new List<Claim>
        {
            new(JwtClaimTypes.Subject, request.Subject),
            new(JwtClaimTypes.JwtId, Guid.NewGuid().ToString("N")),
            new(JwtClaimTypes.IssuedAt, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        if (request.Claims is not null)
        {
            foreach (var kvp in request.Claims)
            {
                if (string.IsNullOrWhiteSpace(kvp.Key))
                {
                    continue;
                }

                claims.Add(new Claim(kvp.Key, kvp.Value));
            }
        }

        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expires.UtcDateTime,
            signingCredentials: creds);

        token.Header[JwtHeaderParameterNames.Kid] = kid;
        token.Header[JwtHeaderParameterNames.Typ] = "JWT";

        var handler = new JwtSecurityTokenHandler();
        var serialized = handler.WriteToken(token);

        _logger.LogInformation("Generated token alg={Alg} kid={Kid} sub={Sub} exp={Exp}", alg, kid, request.Subject, expires);

        return new GenerateTokenResponse(
            Token: serialized,
            Algorithm: alg,
            KeyId: kid,
            IssuedAt: now,
            ExpiresAt: expires);
    }

    public async Task<ValidateTokenResponse> ValidateAsync(ValidateTokenRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
        {
            return new ValidateTokenResponse(false, "Token is empty", null, null, null);
        }

        var handler = new JwtSecurityTokenHandler();
        JwtSecurityToken? jwt;

        try
        {
            jwt = handler.ReadJwtToken(request.Token);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read token");
            return new ValidateTokenResponse(false, "Invalid JWT format", null, null, null);
        }

        var alg = jwt.Header.Alg ?? string.Empty;
        var kid = jwt.Header.Kid;

        var key = await _keys.TryResolveValidationKeyAsync(kid, alg, ct);
        if (key is null)
        {
            return new ValidateTokenResponse(false, "Signing key not found", alg, kid, null);
        }

        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,

            ValidateIssuer = request.ValidateIssuerAudience,
            ValidIssuer = _options.Issuer,

            ValidateAudience = request.ValidateIssuerAudience,
            ValidAudience = _options.Audience,

            ValidateLifetime = request.ValidateLifetime,
            ClockSkew = TimeSpan.FromSeconds(5)
        };

        try
        {
            handler.ValidateToken(request.Token, parameters, out var validatedToken);

            var jwtValidated = (JwtSecurityToken)validatedToken;
            var payload = jwtValidated.Claims.ToDictionary(c => c.Type, c => (object)c.Value, StringComparer.Ordinal);

            return new ValidateTokenResponse(true, null, alg, kid, payload);
        }
        catch (Exception ex)
        {
            _logger.LogInformation(ex, "Token validation failed alg={Alg} kid={Kid}", alg, kid);
            return new ValidateTokenResponse(false, ex.Message, alg, kid, null);
        }
    }

    private static string MapSigningAlgorithm(string alg) => alg switch
    {
        JwtAlgorithms.RS256 => SecurityAlgorithms.RsaSha256,
        JwtAlgorithms.HS256 => SecurityAlgorithms.HmacSha256,
        JwtAlgorithms.ES256 => SecurityAlgorithms.EcdsaSha256,
        _ => throw new InvalidOperationException($"Unsupported algorithm '{alg}'")
    };
}
