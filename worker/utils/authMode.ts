/**
 * Authentication Mode Utilities
 * Determines whether to use cookie-based or token-based authentication
 */

export type AuthMode = 'cookie' | 'token';

/**
 * Get authentication mode for a request
 * Defaults to 'cookie' for localhost, 'token' for workers.dev
 * Can be overridden with AUTH_MODE environment variable
 */
export function getAuthMode(request: Request, env: { AUTH_MODE?: string }): AuthMode {
	// If explicitly set in environment, use that
	if (env.AUTH_MODE === 'cookie' || env.AUTH_MODE === 'token') {
		return env.AUTH_MODE;
	}

	// Auto-detect based on request origin
	const url = new URL(request.url);
	const hostname = url.hostname;

	// Default to cookie for localhost
	if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname.includes('localhost')) {
		return 'cookie';
	}

	// Default to token for workers.dev
	if (hostname.includes('.workers.dev')) {
		return 'token';
	}

	// Default to cookie for other domains (custom domains)
	return 'cookie';
}

/**
 * Check if cookie-based authentication should be used
 */
export function shouldUseCookieAuth(request: Request, env: { AUTH_MODE?: string }): boolean {
	return getAuthMode(request, env) === 'cookie';
}

/**
 * Check if token-based authentication should be used
 */
export function shouldUseTokenAuth(request: Request, env: { AUTH_MODE?: string }): boolean {
	return getAuthMode(request, env) === 'token';
}

