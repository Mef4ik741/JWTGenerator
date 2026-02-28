using FluentValidation;
using JwtGenerator.Constants;
using JwtGenerator.Contracts;

namespace JwtGenerator.Validation;

public sealed class GenerateTokenRequestValidator : AbstractValidator<GenerateTokenRequest>
{
    public GenerateTokenRequestValidator()
    {
        RuleFor(x => x.Subject)
            .NotEmpty()
            .MaximumLength(200);

        RuleFor(x => x.Algorithm)
            .Must(a => a is null || a.Trim().ToUpperInvariant() is JwtAlgorithms.RS256 or JwtAlgorithms.HS256 or JwtAlgorithms.ES256)
            .WithMessage("Algorithm must be RS256, HS256 or ES256");

        RuleFor(x => x.LifetimeMinutes)
            .Must(m => m is null || m is >= 1 and <= 24 * 60)
            .WithMessage("LifetimeMinutes must be between 1 and 1440");

        RuleForEach(x => x.Claims)
            .Must(kvp => !string.IsNullOrWhiteSpace(kvp.Key))
            .WithMessage("Claim key must not be empty");
    }
}
