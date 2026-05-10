using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AuthService;

public static class AspNetCoreAuthServiceExtensions
{
    public static IApplicationBuilder UseAuthService(this IApplicationBuilder app, AuthServiceJwtVerifier verifier)
    {
        return app.Use(async (context, next) =>
        {
            try
            {
                var header = context.Request.Headers.Authorization.ToString();
                var token = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..] : "";
                context.Items["authservice"] = await verifier.VerifyAsync(token, ct: context.RequestAborted);
                await next();
            }
            catch
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "unauthorized" });
            }
        });
    }
}
