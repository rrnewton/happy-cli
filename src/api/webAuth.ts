import { encodeBase64 } from './encryption';
import { configuration } from '@/configuration';

/**
 * Generate a URL for web authentication
 *
 * The URL includes:
 * - key: The ephemeral public key for the connection
 * - server: The server URL (only if using a non-production server)
 *
 * @param publicKey - The ephemeral public key to include in the URL
 * @returns The web authentication URL
 */
export function generateWebAuthUrl(publicKey: Uint8Array): string {
    const publicKeyBase64 = encodeBase64(publicKey, 'base64url');
    const baseUrl = `${configuration.webappUrl}/terminal/connect#key=${publicKeyBase64}`;

    // Include server URL in the link for self-hosted setups
    // This allows the webapp to know which server to authenticate against
    const productionServerUrl = 'https://api.cluster-fluster.com';
    if (configuration.serverUrl !== productionServerUrl) {
        const encodedServerUrl = encodeURIComponent(configuration.serverUrl);
        return `${baseUrl}&server=${encodedServerUrl}`;
    }

    return baseUrl;
}