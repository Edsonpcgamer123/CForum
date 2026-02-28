/**
 * Cloudflare Pages Functions - API Proxy to Worker
 * Routes /api/* requests to Worker, handles static assets and HTML routing
 */

export const onRequest: PagesFunction = async (context) => {
	const { request, env } = context;
	const url = new URL(request.url);
	const pathname = url.pathname;
	const isApiRoute = pathname.startsWith('/api/');
	const isR2Route = pathname.startsWith('/r2/');

	if (!isApiRoute && !isR2Route) {
		return context.next();
	}

	const corsHeaders = {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS, PUT, DELETE',
		'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Timestamp, X-Nonce',
	};

	if (request.method === 'OPTIONS') {
		return new Response(null, { headers: corsHeaders });
	}

	try {
		const isLocalDev = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
		let workerUrl = (env.WORKER_URL as string) ||
			(isLocalDev ? 'http://localhost:8787' : 'https://cforum.adysec.workers.dev');

		if (!workerUrl.startsWith('http')) {
			console.warn(`⚠️ Invalid WORKER_URL: ${workerUrl}`);
			workerUrl = isLocalDev ? 'http://localhost:8787' : 'https://cforum.adysec.workers.dev';
		}

		console.log(`↔️ Proxying request to Worker: ${workerUrl}${pathname}`);

		const forwardUrl = new URL(pathname + url.search, workerUrl);

		const forwardHeaders = new Headers(request.headers);
		forwardHeaders.set('X-Forwarded-Proto', url.protocol.replace(':', ''));
		forwardHeaders.set('X-Forwarded-Host', url.hostname);
		forwardHeaders.set('X-Original-URL', url.origin);

		const response = await fetch(new Request(forwardUrl.toString(), {
			method: request.method,
			headers: forwardHeaders,
			body: request.body,
		}));

		const headers = new Headers(response.headers);
		Object.entries(corsHeaders).forEach(([key, val]) => headers.set(key, val));

		return new Response(response.body, {
			status: response.status,
			statusText: response.statusText,
			headers,
		});

	} catch (error) {
		console.error('❌ API proxy error:', error);
		return Response.json(
			{
				error: 'Failed to forward API request',
				message: String(error),
			},
			{ status: 502, headers: corsHeaders }
		);
	}
};
