/**
 * ParentAuthListener Component
 * Listens for authentication tokens from parent application via postMessage
 * Used for iframe auto-login scenarios
 */

import { useEffect } from 'react';

const PARENT_APP_DOMAIN = import.meta.env.VITE_PARENT_APP_DOMAIN;

export function ParentAuthListener() {
	useEffect(() => {
		const handleMessage = (event: MessageEvent) => {
			// Optional: Verify origin
			if (PARENT_APP_DOMAIN && event.origin !== PARENT_APP_DOMAIN) {
				console.warn(
					'Ignoring message from unauthorized origin:',
					event.origin,
				);
				return;
			}

			if (
				event.data.type === 'vibesdk-auth' ||
				event.data.type === 'vibesdk-refresh-token'
			) {
				if (event.data.token) {
					// Store token in localStorage
					localStorage.setItem('vibesdk_token', event.data.token);
					console.log(
						'[VibeSDK] Token received from parent and stored',
					);
				}
			}
		};

		window.addEventListener('message', handleMessage);
		return () => window.removeEventListener('message', handleMessage);
	}, []);

	return null;
}

