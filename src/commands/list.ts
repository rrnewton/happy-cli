/**
 * List active sessions command
 *
 * Fetches active sessions from the server and displays them in a user-friendly format.
 */

import { configuration } from '@/configuration';
import { Credentials } from '@/persistence';
import axios from 'axios';
import { decrypt, decodeBase64, libsodiumDecryptFromPublicKey, libsodiumPublicKeyFromSecretKey } from '@/api/encryption';
import { logger } from '@/ui/logger';
import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { createHash } from 'crypto';
import tweetnacl from 'tweetnacl';

interface SessionResponse {
    id: string;
    metadata: string | null;  // Base64 encrypted
    metadataVersion: number;
    agentState: string | null;  // Base64 encrypted
    agentStateVersion: number;
    active: boolean;
    activeAt: number;  // Unix timestamp in milliseconds
    createdAt: number;
    updatedAt: number;
    dataEncryptionKey: string | null;  // Base64 encrypted encryption key
}

interface Metadata {
    path?: string;
    host?: string;
    summary?: {
        text: string;
        updatedAt: number;
    };
    claudeSessionId?: string;
    [key: string]: any;
}

interface AgentState {
    thinking?: boolean;
    [key: string]: any;
}

/**
 * Decrypt a dataEncryptionKey using the user's public key credentials
 */
function decryptDataEncryptionKey(encryptedKey: string, credentials: Credentials): Uint8Array | null {
    try {
        logger.debug(`Attempting to decrypt dataEncryptionKey...`);
        logger.debug(`Credentials type: ${credentials.encryption.type}`);

        if (credentials.encryption.type !== 'dataKey') {
            logger.debug(`Credentials type is not 'dataKey', returning null`);
            return null;
        }

        const encryptedBundle = decodeBase64(encryptedKey);
        logger.debug(`Encrypted bundle length: ${encryptedBundle.length}`);
        logger.debug(`Version byte: ${encryptedBundle[0]}`);

        if (encryptedBundle.length === 0 || encryptedBundle[0] !== 0) {
            logger.debug(`Invalid version or empty bundle`);
            return null; // Invalid version or empty
        }

        // Remove version byte and decrypt the rest
        const bundleWithoutVersion = encryptedBundle.slice(1);
        logger.debug(`Bundle without version length: ${bundleWithoutVersion.length}`);

        // The publicKey field is actually the contentDataKey seed from the web client (already Uint8Array)
        // Derive the keypair from this seed using libsodium's crypto_box_seed_keypair approach
        const seedBytes = credentials.encryption.publicKey;
        logger.debug(`Seed bytes from publicKey: ${seedBytes.length} bytes`);

        // libsodium's crypto_box_seed_keypair: hash the seed with SHA-512, use first 32 bytes as secret key
        const hash = createHash('sha512').update(Buffer.from(seedBytes)).digest();
        const secretKey = new Uint8Array(hash.slice(0, 32));
        const keypair = tweetnacl.box.keyPair.fromSecretKey(secretKey);
        logger.debug(`Derived keypair from publicKey seed`);

        // Decrypt using the derived secret key
        const decrypted = libsodiumDecryptFromPublicKey(bundleWithoutVersion, keypair.secretKey);
        logger.debug(`Decryption result: ${decrypted ? `success (${decrypted.length} bytes)` : 'null'}`);
        return decrypted;
    } catch (error) {
        logger.debug(`Failed to decrypt dataEncryptionKey:`, error);
        return null;
    }
}

/**
 * Get current working directory from Claude session file
 */
function getCurrentWorkingDirectory(claudeSessionId: string, spawnDirectory: string): string {
    try {
        const homeDir = homedir();
        const claudeProjectsDir = join(homeDir, '.claude', 'projects');

        if (!existsSync(claudeProjectsDir)) {
            return spawnDirectory;
        }

        // Find all project directories
        const projectDirs = readdirSync(claudeProjectsDir)
            .map(name => join(claudeProjectsDir, name))
            .filter(path => statSync(path).isDirectory());

        // Search for the session file
        for (const projectDir of projectDirs) {
            const sessionFile = join(projectDir, `${claudeSessionId}.jsonl`);
            if (existsSync(sessionFile)) {
                // Read the last line to get current working directory
                const content = readFileSync(sessionFile, 'utf8');
                const lines = content.trim().split('\n');
                const lastLine = lines[lines.length - 1];

                try {
                    const lastMessage = JSON.parse(lastLine);
                    if (lastMessage.cwd) {
                        return lastMessage.cwd;
                    }
                } catch (e) {
                    logger.debug(`Failed to parse last line of session file ${sessionFile}:`, e);
                }
            }
        }
    } catch (error) {
        logger.debug(`Failed to get current working directory for session ${claudeSessionId}:`, error);
    }

    // Fall back to spawn directory
    return spawnDirectory;
}

/**
 * List all active sessions
 */
export async function listSessions(credentials: Credentials): Promise<void> {
    try {
        const serverUrl = configuration.serverUrl;

        // Fetch active sessions from server
        const response = await axios.get<{ sessions: SessionResponse[] }>(`${serverUrl}/v2/sessions/active`, {
            headers: {
                'Authorization': `Bearer ${credentials.token}`
            }
        });

        const sessions = response.data.sessions;

        if (sessions.length === 0) {
            console.log('No active sessions found.');
            return;
        }

        console.log(`\nActive Sessions (${sessions.length}):\n`);

        // Display each session
        for (const session of sessions) {
            logger.debug(`\n=== Processing session ${session.id} ===`);
            logger.debug(`Has dataEncryptionKey: ${!!session.dataEncryptionKey}`);
            logger.debug(`Has metadata: ${!!session.metadata}`);

            let metadata: Metadata = {};
            let agentState: AgentState = {};

            // Determine the encryption key to use
            // Priority: dataEncryptionKey (web/mobile sessions) > machineKey (CLI sessions) > secret (legacy)
            let encryptionKey: Uint8Array | null = null;
            let encryptionVariant: 'legacy' | 'dataKey' = 'dataKey';

            if (session.dataEncryptionKey) {
                logger.debug(`Session has dataEncryptionKey, attempting to decrypt...`);
                // Web/mobile session - decrypt the dataEncryptionKey first
                encryptionKey = decryptDataEncryptionKey(session.dataEncryptionKey, credentials);
                if (!encryptionKey) {
                    logger.debug(`Failed to decrypt dataEncryptionKey for session ${session.id}`);
                } else {
                    logger.debug(`Successfully decrypted dataEncryptionKey`);
                }
            } else if (credentials.encryption.type === 'dataKey') {
                logger.debug(`Using machineKey directly for CLI session`);
                // CLI session - use machineKey directly
                encryptionKey = credentials.encryption.machineKey;
            } else {
                logger.debug(`Using legacy secret key`);
                // Legacy session
                encryptionKey = credentials.encryption.secret;
                encryptionVariant = 'legacy';
            }

            logger.debug(`Encryption key available: ${!!encryptionKey}`);
            logger.debug(`Encryption variant: ${encryptionVariant}`);

            // Decrypt metadata if present and we have a key
            if (session.metadata && encryptionKey) {
                logger.debug(`Attempting to decrypt metadata...`);
                try {
                    const metadataBytes = decodeBase64(session.metadata);
                    logger.debug(`Metadata bytes length: ${metadataBytes.length}`);
                    const decrypted = decrypt(
                        encryptionKey,
                        encryptionVariant,
                        metadataBytes
                    );
                    if (decrypted) {
                        logger.debug(`Successfully decrypted metadata:`, JSON.stringify(decrypted));
                        metadata = decrypted;
                    } else {
                        logger.debug(`Decrypt returned null`);
                    }
                } catch (error) {
                    logger.debug(`Failed to decrypt metadata for session ${session.id}:`, error);
                }
            } else {
                if (!session.metadata) {
                    logger.debug(`No metadata to decrypt`);
                }
                if (!encryptionKey) {
                    logger.debug(`No encryption key available`);
                }
            }

            // Decrypt agent state if present and we have a key
            if (session.agentState && encryptionKey) {
                try {
                    const decrypted = decrypt(
                        encryptionKey,
                        encryptionVariant,
                        decodeBase64(session.agentState)
                    );
                    if (decrypted) {
                        agentState = decrypted;
                    }
                } catch (error) {
                    logger.debug(`Failed to decrypt agent state for session ${session.id}:`, error);
                }
            }

            // Format and display session info
            // Title priority: summary.text > last path segment > (Untitled)
            let title = '(Untitled)';
            if (metadata.summary?.text) {
                title = metadata.summary.text;
            } else if (metadata.path) {
                const segments = metadata.path.split('/').filter(Boolean);
                if (segments.length > 0) {
                    title = segments[segments.length - 1];
                }
            }
            const host = metadata.host || '(Unknown)';
            const thinking = agentState.thinking ? '🤔 Thinking' : '💤 Idle';

            // Get current working directory - prefer live cwd from Claude session file
            let workingDir = metadata.path || '(Unknown)';
            if (metadata.claudeSessionId && metadata.path) {
                workingDir = getCurrentWorkingDirectory(metadata.claudeSessionId, metadata.path);
            }

            console.log(`  ID: ${session.id}`);
            console.log(`  Title: ${title}`);
            console.log(`  Working Directory: ${workingDir}`);
            console.log(`  Host: ${host}`);
            console.log(`  Status: ${thinking}`);
            console.log(`  Last Active: ${new Date(session.activeAt).toLocaleString()}`);
            console.log('');
        }
    } catch (error) {
        if (axios.isAxiosError(error)) {
            if (error.response?.status === 401) {
                console.error('Authentication failed. Please run `happy auth` to authenticate.');
            } else {
                console.error(`Failed to fetch sessions: ${error.response?.data?.message || error.message}`);
            }
        } else {
            console.error(`Failed to fetch sessions: ${error}`);
        }
        process.exit(1);
    }
}
