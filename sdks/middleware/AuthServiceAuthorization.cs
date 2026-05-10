using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AuthService.Middleware
{
    public static class AuthServiceAuthorization
    {
        public static string PermissionFor(string resource, string action)
        {
            resource = (resource ?? "").Trim().ToLowerInvariant();
            action = (action ?? "").Trim().ToLowerInvariant();
            return resource.Length == 0 || action.Length == 0 ? "" : resource + ":" + action;
        }

        public static bool IsAuthorized(IEnumerable<Claim> claims, string resource, string action)
        {
            var list = claims?.ToList() ?? new List<Claim>();
            if (list.Any(c => c.Type == "org_role" && c.Value == "owner"))
            {
                return true;
            }
            var permission = PermissionFor(resource, action);
            return list.Any(c => c.Type == "org_permissions" && c.Value == permission);
        }

        public static Func<HttpContext, Func<Task>, Task> RequireAuthorization(string resource, string action)
        {
            return async (context, next) =>
            {
                if (!IsAuthorized(context.User?.Claims, resource, action))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"forbidden\"}");
                    return;
                }
                await next();
            };
        }
    }
}
