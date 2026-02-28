using System.ComponentModel.DataAnnotations;

namespace JwtGenerator.Options;

public sealed class ApiKeyOptions
{
    public const string SectionName = "Security";

    [Required]
    public string ApiKey { get; init; } = string.Empty;
}
