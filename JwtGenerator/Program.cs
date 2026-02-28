using FluentValidation;
using FluentValidation.AspNetCore;
using JwtGenerator;
using JwtGenerator.Abstractions;
using JwtGenerator.Middleware;
using JwtGenerator.Options;
using JwtGenerator.Security;
using JwtGenerator.Services;
using JwtGenerator.Validation;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

var portRaw = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrWhiteSpace(portRaw) && int.TryParse(portRaw, out var parsedPort))
{
    builder.WebHost.UseUrls($"http://0.0.0.0:{parsedPort}");
}

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "JwtGenerator API",
        Version = "v1",
        Description = "Mock JWT Issuer for development and testing"
    });

    options.AddSecurityDefinition("ApiKey", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Name = "X-API-KEY",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter your API key (e.g., dev-secret for development)"
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "ApiKey"
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.AddControllers();
builder.Services.AddFluentValidationAutoValidation();

builder.Services
    .AddOptions<ApiKeyOptions>()
    .Bind(builder.Configuration.GetSection(ApiKeyOptions.SectionName))
    .ValidateDataAnnotations();

builder.Services
    .AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection(JwtOptions.SectionName))
    .ValidateDataAnnotations();

builder.Services.AddSingleton<IKeyMaterialStore, InMemoryKeyMaterialStore>();
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddHostedService<KeyRotationHostedService>();

builder.Services.AddTransient<ExceptionHandlingMiddleware>();
builder.Services.AddTransient<ApiKeyMiddleware>();

builder.Services.AddValidatorsFromAssemblyContaining<GenerateTokenRequestValidator>();

var app = builder.Build();

app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseMiddleware<ApiKeyMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "JwtGenerator API v1");
        options.RoutePrefix = "swagger";
    });
}

app.MapControllers();

app.Run();