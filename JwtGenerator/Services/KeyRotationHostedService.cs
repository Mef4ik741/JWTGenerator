using JwtGenerator.Abstractions;
using Microsoft.Extensions.Options;

namespace JwtGenerator.Services;

public sealed class KeyRotationHostedService : BackgroundService
{
    private readonly IKeyMaterialStore _store;
    private readonly JwtOptions _options;
    private readonly ILogger<KeyRotationHostedService> _logger;

    public KeyRotationHostedService(IKeyMaterialStore store, IOptions<JwtOptions> options, ILogger<KeyRotationHostedService> logger)
    {
        _store = store;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await _store.EnsureInitializedAsync(stoppingToken);

        var interval = TimeSpan.FromMinutes(Math.Max(1, _options.KeyRotationMinutes));
        _logger.LogInformation("Key rotation interval: {Interval}", interval);

        using var timer = new PeriodicTimer(interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await _store.RotateAsync(stoppingToken);
        }
    }
}
