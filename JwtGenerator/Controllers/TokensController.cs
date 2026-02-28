using JwtGenerator.Abstractions;
using JwtGenerator.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace JwtGenerator.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class TokensController : ControllerBase
{
    [HttpPost("generate")]
    public async Task<ActionResult<GenerateTokenResponse>> Generate(
        [FromBody] GenerateTokenRequest request,
        [FromServices] ITokenService tokenService,
        CancellationToken ct)
    {
        var response = await tokenService.GenerateAsync(request, ct);
        return Ok(response);
    }

    [HttpPost("validate")]
    public async Task<ActionResult<ValidateTokenResponse>> Validate(
        [FromBody] ValidateTokenRequest request,
        [FromServices] ITokenService tokenService,
        CancellationToken ct)
    {
        var response = await tokenService.ValidateAsync(request, ct);
        return Ok(response);
    }
}
