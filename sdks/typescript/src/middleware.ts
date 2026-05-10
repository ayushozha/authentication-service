import { AuthServiceJwtVerifier } from "./index.js";

function bearer(header?: string): string {
  const parts = String(header || "").split(" ");
  return parts.length === 2 && /^bearer$/i.test(parts[0]) ? parts[1] : "";
}

export function expressAuth(verifier: AuthServiceJwtVerifier) {
  return async (req: any, res: any, next: any) => {
    try {
      req.auth = await verifier.verify(bearer(req.headers.authorization));
      next();
    } catch (err: any) {
      res.status(401).json({ error: err.message || "unauthorized" });
    }
  };
}

export function fastifyAuth(verifier: AuthServiceJwtVerifier) {
  return async (request: any, reply: any) => {
    try {
      request.auth = await verifier.verify(bearer(request.headers.authorization));
    } catch (err: any) {
      reply.code(401).send({ error: err.message || "unauthorized" });
    }
  };
}

export function nextAuth(verifier: AuthServiceJwtVerifier) {
  return async function middleware(request: any) {
    const token = bearer(request.headers.get ? request.headers.get("authorization") : request.headers.authorization);
    await verifier.verify(token);
    return undefined;
  };
}

export function nestjsAuthGuard(verifier: AuthServiceJwtVerifier) {
  return class AuthServiceGuard {
    async canActivate(context: any) {
      const req = context.switchToHttp().getRequest();
      req.auth = await verifier.verify(bearer(req.headers.authorization));
      return true;
    }
  };
}
