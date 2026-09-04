import { NextRequest, NextResponse } from "next/server";

const METHODS_WITHOUT_BODY = new Set(["GET", "HEAD"]);
type RouteContext = { params: Promise<{ path: string[] }> };

async function proxy(request: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const backendUrl = (process.env.BACKEND_API_URL || "http://localhost:8000").replace(/\/$/, "");
  const target = `${backendUrl}/${path.map(encodeURIComponent).join("/")}${request.nextUrl.search}`;
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("content-length");

  if (process.env.BACKEND_API_KEY) {
    headers.set("X-API-Key", process.env.BACKEND_API_KEY);
  }

  const response = await fetch(target, {
    method: request.method,
    headers,
    body: METHODS_WITHOUT_BODY.has(request.method) ? undefined : await request.arrayBuffer(),
    redirect: "manual",
  });
  const responseHeaders = new Headers(response.headers);
  responseHeaders.delete("content-encoding");
  responseHeaders.delete("content-length");
  return new NextResponse(response.body, { status: response.status, headers: responseHeaders });
}

export const GET = proxy;
export const POST = proxy;
export const PATCH = proxy;
export const PUT = proxy;
export const DELETE = proxy;
export const OPTIONS = proxy;
