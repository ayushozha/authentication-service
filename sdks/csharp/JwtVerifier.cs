using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;

namespace AuthService;

public sealed class AuthServiceJwtVerifier
{
    private readonly ConfigurationManager<OpenIdConnectConfiguration> _config;
    private readonly TokenValidationParameters _parameters;

    public AuthServiceJwtVerifier(string jwksUrl, string? issuer = null, string? audience = null)
    {
        _config = new ConfigurationManager<OpenIdConnectConfiguration>(jwksUrl, new OpenIdConnectConfigurationRetriever());
        _parameters = new TokenValidationParameters { ValidateIssuer = issuer is not null, ValidIssuer = issuer, ValidateAudience = audience is not null, ValidAudience = audience, ValidateIssuerSigningKey = true, ValidateLifetime = true };
    }

    public async Task<JwtSecurityToken> VerifyAsync(string token, string? clientId = null, string? tokenUse = null, IEnumerable<string>? scopes = null, IEnumerable<string>? orgPermissions = null, CancellationToken ct = default)
    {
        var config = await _config.GetConfigurationAsync(ct);
        _parameters.IssuerSigningKeys = config.SigningKeys;
        new JwtSecurityTokenHandler().ValidateToken(token, _parameters, out var validated);
        var jwt = (JwtSecurityToken)validated;
        if (clientId is not null && jwt.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value != clientId) throw new SecurityTokenException("token client mismatch");
        if (tokenUse is not null && jwt.Claims.FirstOrDefault(c => c.Type == "token_use")?.Value != tokenUse) throw new SecurityTokenException("token_use mismatch");
        var claimScopes = jwt.Claims.Where(c => c.Type == "scopes").Select(c => c.Value).Concat((jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToHashSet();
        foreach (var scope in scopes ?? Array.Empty<string>()) if (!claimScopes.Contains(scope)) throw new SecurityTokenException("missing scope " + scope);
        var role = jwt.Claims.FirstOrDefault(c => c.Type == "org_role")?.Value;
        var perms = jwt.Claims.Where(c => c.Type == "org_permissions").Select(c => c.Value).ToHashSet();
        foreach (var permission in orgPermissions ?? Array.Empty<string>()) if (role != "owner" && !perms.Contains(permission)) throw new SecurityTokenException("missing organization permission " + permission);
        return jwt;
    }

    public static bool VerifyWebhookSignature(string secret, string timestamp, string signature, byte[] body)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var expected = "v1=" + Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(timestamp + ".").Concat(body).ToArray())).ToLowerInvariant();
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(signature ?? ""));
    }
}
