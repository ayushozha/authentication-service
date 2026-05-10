package com.authservice.sdk;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

public class SpringBootAuthServiceFilter extends OncePerRequestFilter {
  private final JwtVerifier verifier;

  public SpringBootAuthServiceFilter(JwtVerifier verifier) {
    this.verifier = verifier;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
    try {
      String header = request.getHeader("Authorization");
      String token = header != null && header.toLowerCase().startsWith("bearer ") ? header.substring(7) : "";
      request.setAttribute("authservice", verifier.verify(token));
      chain.doFilter(request, response);
    } catch (Exception ex) {
      response.setStatus(401);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"unauthorized\"}");
    }
  }
}
