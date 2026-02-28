using JwtGenerator.Options;
using Microsoft.Extensions.Options;

namespace JwtGenerator.Middleware;

public sealed class ApiKeyMiddleware : IMiddleware
{
    public const string HeaderName = "X-API-KEY";

    private readonly ApiKeyOptions _options;
    private readonly ILogger<ApiKeyMiddleware> _logger;

    public ApiKeyMiddleware(IOptions<ApiKeyOptions> options, ILogger<ApiKeyMiddleware> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var env = context.RequestServices.GetService<IHostEnvironment>();
        if (env is not null && env.IsDevelopment() &&
            context.Request.Path.StartsWithSegments("/swagger", StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        if (!context.Request.Headers.TryGetValue(HeaderName, out var apiKey) || string.IsNullOrWhiteSpace(apiKey))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Missing X-API-KEY header" });
            return;
        }

        if (!string.Equals(apiKey.ToString(), _options.ApiKey, StringComparison.Ordinal))
        {
            _logger.LogWarning("Invalid API key from {RemoteIp}", context.Connection.RemoteIpAddress);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Invalid API key" });
            return;
        }

        await next(context);
    }
}
