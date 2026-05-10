package com.authservice.sdk;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URL;
import java.util.List;

public class JwtVerifier {
  private final ConfigurableJWTProcessor<com.nimbusds.jose.proc.SecurityContext> processor = new DefaultJWTProcessor<>();
  private final String clientId;
  private final String tokenUse;
  private final List<String> scopes;
  private final List<String> orgPermissions;

  public JwtVerifier(String jwksUrl, String clientId, String tokenUse, List<String> scopes, List<String> orgPermissions) throws Exception {
    processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new RemoteJWKSet<>(new URL(jwksUrl))));
    this.clientId = clientId;
    this.tokenUse = tokenUse;
    this.scopes = scopes == null ? List.of() : scopes;
    this.orgPermissions = orgPermissions == null ? List.of() : orgPermissions;
  }

  public JWTClaimsSet verify(String token) throws Exception {
    JWTClaimsSet claims = processor.process(token, null);
    if (clientId != null && !clientId.equals(claims.getStringClaim("client_id"))) throw new SecurityException("token client mismatch");
    if (tokenUse != null && !tokenUse.equals(claims.getStringClaim("token_use"))) throw new SecurityException("token_use mismatch");
    String scope = claims.getStringClaim("scope");
    List<String> claimScopes = claims.getStringListClaim("scopes");
    for (String required : scopes) if ((claimScopes == null || !claimScopes.contains(required)) && (scope == null || !List.of(scope.split(" ")).contains(required))) throw new SecurityException("missing scope " + required);
    List<String> perms = claims.getStringListClaim("org_permissions");
    for (String required : orgPermissions) if (!"owner".equals(claims.getStringClaim("org_role")) && (perms == null || !perms.contains(required))) throw new SecurityException("missing organization permission " + required);
    return claims;
  }
}
