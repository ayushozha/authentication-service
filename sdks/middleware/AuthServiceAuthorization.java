package com.authservice.middleware;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

public final class AuthServiceAuthorization {
    private AuthServiceAuthorization() {}

    public static String permissionFor(String resource, String action) {
        String normalizedResource = resource == null ? "" : resource.trim().toLowerCase();
        String normalizedAction = action == null ? "" : action.trim().toLowerCase();
        if (normalizedResource.isEmpty() || normalizedAction.isEmpty()) {
            return "";
        }
        return normalizedResource + ":" + normalizedAction;
    }

    @SuppressWarnings("unchecked")
    public static boolean isAuthorized(Map<String, Object> claims, String resource, String action) {
        if (claims == null) {
            return false;
        }
        if ("owner".equals(claims.get("org_role"))) {
            return true;
        }
        Object permissions = claims.get("org_permissions");
        return permissions instanceof List && ((List<String>) permissions).contains(permissionFor(resource, action));
    }

    public static Filter servletFilter(String resource, String action, Function<ServletRequest, Map<String, Object>> claimsGetter) {
        return new Filter() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
                if (!isAuthorized(claimsGetter.apply(request), resource, action)) {
                    HttpServletResponse http = (HttpServletResponse) response;
                    http.setStatus(403);
                    http.setContentType("application/json");
                    http.getWriter().write("{\"error\":\"forbidden\"}");
                    return;
                }
                chain.doFilter(request, response);
            }
        };
    }
}
