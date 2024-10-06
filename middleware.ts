"use server";

import { NextRequest, NextResponse } from "next/server";
import { jwtVerify, importSPKI, JWTPayload } from "jose";

const JWT_PUBLIC_KEY_BASE64 = process.env.USERFRONT_JWT_PUBLIC_KEY!;

interface UserFrontJwtPayload extends JWTPayload {
  userId?: string;
}

async function verifyToken(token: string, publicKeyBase64: string) {
  try {
    const publicKey = await importSPKI(
      Buffer.from(publicKeyBase64, "base64").toString("utf-8"),
      "RS256"
    );
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ["RS256"],
    });
    return payload as UserFrontJwtPayload;
  } catch (error) {
    console.log("JWT verification failed:", error);
    return null;
  }
}

/*
 * Match all request paths except for the ones starting with:
 * - api (API routes)
 * - _next/static (static files)
 * - _next/image (image optimization files)
 * - favicon.ico (favicon file)
 */
const pathsToExclude =
  /^(?!\/(api|_next\/static|favicon\.ico|manifest|icon|static|mergn)).*$/;

// set of public pages that needed to be excluded from middleware
const publicPagesSet = new Set<string>(["/home"]);

const privatePagesSet = new Set<string>(["/dashboard"]);

const rootRegex = /^\/($|\?.+|#.+)?$/;

export default async function middleware(req: NextRequest) {
  // let go of the request if it's in pathsToExclude or publicPagesSet
  if (
    !pathsToExclude.test(req.nextUrl.pathname) ||
    publicPagesSet.has(req.nextUrl.pathname)
  )
    return NextResponse.next();

  const accessToken = req.cookies.get(
    `access.${process.env.NEXT_PUBLIC_USERFRONT_WORKSPACE_ID}`
  )?.value;

  const decoded = accessToken
    ? await verifyToken(accessToken, JWT_PUBLIC_KEY_BASE64)
    : null;

  const isAuthenticated = decoded && decoded.userId;

  // if user goes to root path '/' then redirect as there is no root page
  // remove this if block if you have a root page

  // redirect to:
  // /dashboard if authenticated
  // /login if unauthenticated
  if (rootRegex.test(req.nextUrl.pathname)) {
    if (isAuthenticated)
      return NextResponse.redirect(
        new URL("/dashboard", req.url)
      ) as NextResponse;
    return NextResponse.redirect(new URL("/login", req.url)) as NextResponse;
  }

  // redirects user from private pages if unauthenticated
  if (privatePagesSet.has(req.nextUrl.pathname) && !isAuthenticated) {
    return NextResponse.redirect(new URL("/login", req.url)) as NextResponse;
  }

  // redirects user from '/login' if authenticated
  if (req.nextUrl.pathname.startsWith("/login") && isAuthenticated) {
    return NextResponse.redirect(
      new URL("/dashboard", req.url)
    ) as NextResponse;
  }
}
