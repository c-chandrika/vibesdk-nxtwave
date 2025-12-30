/**
 * Route Context Types
 */

import { GlobalConfigurableSettings } from '../../config';
import { AuthUser } from '../../types/auth-types';

/**
 * Agent context containing user and session information for agent operations
 */
export interface AgentContext {
	userId: string;
	sessionId: string;
	environment: string;
}

/**
 * Route context containing authenticated user and path parameters
 */
export interface RouteContext {
	/**
	 * Authenticated user (null if not authenticated or public route)
	 */
	user: AuthUser | null;

    /**
     * Session ID (null if not authenticated or public route)
     */
    sessionId: string | null;

    /**
     * Global configurations for the application
     */
    config: GlobalConfigurableSettings;

	/**
	 * Path parameters extracted from the route (e.g., :id, :agentId)
	 */
	pathParams: Record<string, string>;

	/**
	 * Query parameters from the URL
	 */
	queryParams: URLSearchParams;

	/**
	 * Agent context for agent operations (set before invoking agent logic)
	 */
	agentContext?: AgentContext;
}

/**
 * Extended request handler that receives structured context
 */
export type ContextualRequestHandler = (
	request: Request,
	env: Env,
	ctx: ExecutionContext,
	context: RouteContext,
) => Promise<Response>;

/**
 * Route parameter configuration for type safety
 */
export interface RouteParamConfig {
	/**
	 * Required path parameters for this route
	 */
	requiredParams?: string[];

	/**
	 * Optional path parameters for this route
	 */
	optionalParams?: string[];
}

