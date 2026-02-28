using JwtGenerator.Contracts;

namespace JwtGenerator.Abstractions;

public interface ITokenService
{
    Task<GenerateTokenResponse> GenerateAsync(GenerateTokenRequest request, CancellationToken ct);
    Task<ValidateTokenResponse> ValidateAsync(ValidateTokenRequest request, CancellationToken ct);
}
