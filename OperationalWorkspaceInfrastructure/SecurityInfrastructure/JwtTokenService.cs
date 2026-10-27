using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OperationalWorkspace.Domain.Entities;
using OperationalWorkspaceApplication.DTOs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace OperationalWorkspaceInfrastructure.SecurityInfrastructure;

public class JwtTokenService
{
    private readonly IConfiguration _config;

    public JwtTokenService(IConfiguration config)
    {
        _config = config;
    }

    // ======================================================
    // GENERATE ACCESS + REFRESH TOKENS
    // ======================================================

    public AuthTokenResponseDto GenerateTokens(UserAccount user)
    {
        var jwt = _config.GetSection("Jwt");
        var secretKey = jwt["Key"];

        // ======================================================
        // STRICT SECURITY KEY VALIDATION (NO FALLBACKS)
        // ======================================================
        if (string.IsNullOrWhiteSpace(secretKey) || secretKey.Length < 32)
        {
            throw new InvalidOperationException(
                "CRITICAL SECURITY FAILURE: The JWT Signing Key configuration is missing or falls short of the required 256-bit parameter depth.");
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

        // ======================================================
        // SIGNING CREDS
        // ======================================================
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // ======================================================
        // SHORT-LIVED ACCESS TOKEN (DEFAULT LOWERED TO 15 MINS)
        // ======================================================
        var expirationMinutes = Convert.ToDouble(jwt["AccessTokenMinutes"] ?? "15");
        var currentUtcTime = DateTimeOffset.UtcNow;
        var expiresAt = currentUtcTime.AddMinutes(expirationMinutes);

        // ======================================================
        // CLAIMS
        // ======================================================
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("userId", user.Id.ToString()),
            new Claim("username", user.Username),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("email", user.Email ?? string.Empty),
            new Claim("isActive", user.IsActive.ToString().ToLowerInvariant())
        };

        // ======================================================
        // BUILD JWT
        // ======================================================
        var token = new JwtSecurityToken(
            issuer: jwt["Issuer"],
            audience: jwt["Audience"],
            claims: claims,
            notBefore: currentUtcTime.UtcDateTime,
            expires: expiresAt.UtcDateTime,
            signingCredentials: creds
        );

        // ======================================================
        // SERIALIZE ACCESS TOKEN
        // ======================================================
        var accessToken = new JwtSecurityTokenHandler().WriteToken(token);

        // ======================================================
        // GENERATE REFRESH TOKEN
        // ======================================================
        var refreshToken = GenerateRefreshToken();

        // ======================================================
        // RETURN TOKEN RESPONSE
        // ======================================================
        return new AuthTokenResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAtUtc = expiresAt.UtcDateTime
        };
    }

    // ======================================================
    // SECURE REFRESH TOKEN GENERATOR
    // ======================================================
    private string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        return Convert.ToBase64String(randomBytes);
    }
}
