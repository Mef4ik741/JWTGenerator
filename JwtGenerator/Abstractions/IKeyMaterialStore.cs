using JwtGenerator.Contracts;

namespace JwtGenerator.Abstractions;

public interface IKeyMaterialStore
{
    Task EnsureInitializedAsync(CancellationToken ct);
    Task RotateAsync(CancellationToken ct);

    Task<(string KeyId, string Algorithm, Microsoft.IdentityModel.Tokens.SecurityKey Key)> GetSigningKeyAsync(string algorithm, CancellationToken ct);
    Task<Microsoft.IdentityModel.Tokens.SecurityKey?> TryResolveValidationKeyAsync(string? kid, string algorithm, CancellationToken ct);

    Task<JwksResponse> GetJwksAsync(CancellationToken ct);
}
