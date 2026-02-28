/**
 * Cloudflare Pages Functions - Unified Entry Point
 * 
 * 架构优化（单域名方案）：
 * ┌─ 用户访问 forum.example.com
 * │
 * ├─ /api/* → Pages Functions 拦截 → 代理给 Worker
 * │           (D1/R2 数据库操作, 1000+ 请求/月 平均成本 $0.50)
 * │
 * ├─ 静态文件 (*.js/*.css/*.html) → Pages CDN 返回
 * │           (免费无限请求)
 * │
 * └─ 其他路由 (/, /user, /post/*, etc.) → context.next() → index.html
 *           (Pages 自动处理，由前端 React Router 接管)
 *
 * 结果：单一域名，自动路由，节省 ~90% Worker 成本！
 */

export const onRequest: PagesFunction = async (context) => {
	const { request, env } = context;
	const url = new URL(request.url);
	const pathname = url.pathname;

	// ===== 第1步：检查是否是 API 请求 =====
	// 只有 /api/* 需要代理给 Worker，其他都交给 Pages 处理
	if (!pathname.startsWith('/api/')) {
		// 非 API 请求：returns static file or index.html (handled by Pages)
		return context.next();
	}

	// ===== 第2步：API 请求处理 - 代理给 Worker =====
	const corsHeaders = {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS, PUT, DELETE',
		'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Timestamp, X-Nonce',
	};

	// Handle OPTIONS (CORS preflight)
	if (request.method === 'OPTIONS') {
		return new Response(null, { headers: corsHeaders });
	}

	try {
		// 获取 Worker URL - 优先级从高到低
		const isLocalDev = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
		let workerUrl = (env.WORKER_URL as string) ||
			(isLocalDev ? 'http://localhost:8787' : 'https://cforum.adysec.workers.dev');

		// 验证 URL 有效性
		if (!workerUrl.startsWith('http')) {
			console.warn(`⚠️ Invalid WORKER_URL: ${workerUrl}`);
			workerUrl = isLocalDev ? 'http://localhost:8787' : 'https://cforum.adysec.workers.dev';
		}

		console.log(`↔️ Proxying /api request to Worker: ${workerUrl}${pathname}`);

		// 构造转发 URL（保留 query string）
		const forwardUrl = new URL(pathname + url.search, workerUrl);

		// 转发请求给 Worker，并传递原始请求的 origin
		const forwardHeaders = new Headers(request.headers);
		forwardHeaders.set('X-Forwarded-Proto', url.protocol.replace(':', ''));
		forwardHeaders.set('X-Forwarded-Host', url.hostname);
		forwardHeaders.set('X-Original-URL', url.origin);

		const response = await fetch(new Request(forwardUrl.toString(), {
			method: request.method,
			headers: forwardHeaders,
			body: request.body,
		}));

		// 添加 CORS 头并返回
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
