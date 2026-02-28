using JwtGenerator.Abstractions;
using JwtGenerator.Constants;
using JwtGenerator.Contracts;
using JwtGenerator.Options;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace JwtGenerator.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class WellKnownController : ControllerBase
{
    [HttpGet("/.well-known/jwks.json")]
    public async Task<ActionResult<JwksResponse>> GetJwks(
        [FromServices] IKeyMaterialStore store,
        CancellationToken ct)
    {
        var jwks = await store.GetJwksAsync(ct);
        return Ok(jwks);
    }

    [HttpGet("/.well-known/openid-configuration")]
    public ActionResult<OpenIdConfigurationResponse> GetOpenIdConfiguration(
        [FromServices] IOptions<JwtOptions> jwtOptions)
    {
        var baseUrl = $"{Request.Scheme}://{Request.Host.Value}";

        var cfg = new OpenIdConfigurationResponse(
            Issuer: jwtOptions.Value.Issuer,
            JwksUri: $"{baseUrl}/.well-known/jwks.json",
            TokenEndpoint: $"{baseUrl}/api/tokens/generate",
            SupportedSigningAlgs: new[] { JwtAlgorithms.RS256, JwtAlgorithms.HS256, JwtAlgorithms.ES256 });

        return Ok(cfg);
    }
}
