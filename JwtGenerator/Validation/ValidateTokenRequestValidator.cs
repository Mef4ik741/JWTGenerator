using FluentValidation;
using JwtGenerator.Contracts;

namespace JwtGenerator.Validation;

public sealed class ValidateTokenRequestValidator : AbstractValidator<ValidateTokenRequest>
{
    public ValidateTokenRequestValidator()
    {
        RuleFor(x => x.Token)
            .NotEmpty()
            .MaximumLength(10000);
    }
}
