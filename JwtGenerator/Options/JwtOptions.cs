using System.ComponentModel.DataAnnotations;
using JwtGenerator.Constants;

namespace JwtGenerator;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    [Required]
    public string Issuer { get; init; } = "JwtGenerator";

    [Required]
    public string Audience { get; init; } = "local-dev";

    [Required]
    public string DefaultAlgorithm { get; init; } = JwtAlgorithms.RS256;

    [Range(1, 24 * 60)]
    public int TokenLifetimeMinutes { get; init; } = 60;

    [Required]
    [MinLength(32)]
    public string HmacSecret { get; init; } = string.Empty;

    [Range(1, 365 * 24 * 60)]
    public int KeyRotationMinutes { get; init; } = 24 * 60;
}
