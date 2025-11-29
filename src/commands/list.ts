/**
 * List active sessions command
 *
 * Fetches active sessions from the server and displays them in a user-friendly format.
 * Supports filtering by session ID or title, and showing recent messages.
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
import { formatTimeAgo } from '@/utils/time';

export interface ListOptions {
    sessionId?: string;      // -s, --session: filter by session ID (prefix match)
    titleFilter?: string;    // -t, --title: filter by title substring (case-insensitive)
    recentMsgs?: number;     // --recent-msgs N: show N recent messages
    msgLen?: number;         // --msg-len N: max length per message (-1 = unlimited, default 200)
}

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

interface MessageContent {
    c: string;  // Base64 encrypted content
    t: 'encrypted';
}

interface MessageResponse {
    id: string;
    seq: number;
    content: MessageContent;
    localId: string | null;
    createdAt: number;
    updatedAt: number;
}

interface DecryptedMessage {
    role?: 'user' | 'assistant' | 'agent';
    type?: string;
    content?: any;
    meta?: any;
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

        // Derive the keypair from the dataKeySeed using libsodium's crypto_box_seed_keypair approach
        const seedBytes = credentials.encryption.dataKeySeed;
        logger.debug(`Seed bytes from dataKeySeed: ${seedBytes.length} bytes`);

        // libsodium's crypto_box_seed_keypair: hash the seed with SHA-512, use first 32 bytes as secret key
        const hash = createHash('sha512').update(Buffer.from(seedBytes)).digest();
        const secretKey = new Uint8Array(hash.slice(0, 32));
        const keypair = tweetnacl.box.keyPair.fromSecretKey(secretKey);
        logger.debug(`Derived keypair from dataKeySeed`);

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
 * Fetch messages for a session
 */
async function fetchSessionMessages(
    sessionId: string,
    credentials: Credentials,
    encryptionKey: Uint8Array,
    encryptionVariant: 'legacy' | 'dataKey',
    limit: number
): Promise<DecryptedMessage[]> {
    const serverUrl = configuration.serverUrl;

    try {
        const response = await axios.get<{ messages: MessageResponse[] }>(
            `${serverUrl}/v1/sessions/${sessionId}/messages`,
            {
                headers: {
                    'Authorization': `Bearer ${credentials.token}`
                }
            }
        );

        const messages = response.data.messages;
        const decryptedMessages: DecryptedMessage[] = [];

        // Messages come in desc order (newest first), take only what we need
        const messagesToProcess = messages.slice(0, limit);

        for (const msg of messagesToProcess) {
            try {
                // Content is an object with {c: base64, t: 'encrypted'}
                const encryptedContent = msg.content.c;
                const decrypted = decrypt(
                    encryptionKey,
                    encryptionVariant,
                    decodeBase64(encryptedContent)
                );
                if (decrypted) {
                    decryptedMessages.push(decrypted);
                }
            } catch (error) {
                logger.debug(`Failed to decrypt message ${msg.id}:`, error);
            }
        }

        // Reverse to get chronological order (oldest first)
        return decryptedMessages.reverse();
    } catch (error) {
        logger.debug(`Failed to fetch messages for session ${sessionId}:`, error);
        return [];
    }
}

/**
 * Check if a message should be displayed
 * Filters out internal event messages and other non-user-facing content
 */
function shouldDisplayMessage(msg: DecryptedMessage): boolean {
    // Structure: msg.content is the actual message payload
    const msgContent = msg.content;

    // Skip internal event messages (e.g., {type: 'event', data: {type: 'ready'}})
    if (msgContent?.type === 'event') {
        return false;
    }

    return true;
}

/**
 * Format a message for display
 *
 * Message structure from decryption:
 * - User: {role: 'user', content: {type: 'text', text: '...'}, meta: {...}}
 * - Agent output: {role: 'agent', content: {type: 'output', data: {..., message: {content: [{type: 'text', text: '...'}]}}}, meta: {...}}
 * - Agent event: {role: 'agent', content: {type: 'event', data: {...}}}
 */
function formatMessage(msg: DecryptedMessage, indent: string = '', maxLen: number = 200): string {
    // Determine role and prefix from msg.role
    const role = msg.role;
    let prefix: string;

    if (role === 'user') {
        prefix = '👤 User';
    } else if (role === 'agent' || role === 'assistant') {
        prefix = '🤖 Assistant';
    } else {
        prefix = `[${role || 'unknown'}]`;
    }

    // Extract display content based on message structure
    let content = '';
    const msgContent = msg.content;

    if (typeof msgContent === 'string') {
        content = msgContent;
    } else if (msgContent?.type === 'text' && msgContent?.text) {
        // User message: {type: 'text', text: '...'}
        content = msgContent.text;
    } else if (msgContent?.type === 'output' && msgContent?.data?.message?.content) {
        // Agent output: extract text from message.content array
        const messageContent = msgContent.data.message.content;
        if (Array.isArray(messageContent)) {
            content = messageContent
                .filter((c: any) => c.type === 'text')
                .map((c: any) => c.text)
                .join('\n');
        } else if (typeof messageContent === 'string') {
            content = messageContent;
        }
    } else if (Array.isArray(msgContent)) {
        // Claude-style content array
        content = msgContent
            .filter((c: any) => c.type === 'text')
            .map((c: any) => c.text)
            .join('\n');
    } else {
        content = JSON.stringify(msgContent || msg, null, 2);
    }

    // Truncate long messages (maxLen < 0 means unlimited)
    if (maxLen >= 0 && content.length > maxLen) {
        content = content.substring(0, maxLen) + '...';
    }

    // Replace newlines with indented newlines
    content = content.replace(/\n/g, `\n${indent}         `);

    return `${indent}${prefix}: ${content}`;
}

/**
 * List all active sessions
 */
export async function listSessions(credentials: Credentials, options: ListOptions = {}): Promise<void> {
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

        // Process sessions to extract metadata and title for filtering
        interface ProcessedSession {
            session: SessionResponse;
            metadata: Metadata;
            agentState: AgentState;
            encryptionKey: Uint8Array | null;
            encryptionVariant: 'legacy' | 'dataKey';
            title: string;
            host: string;
            workingDir: string;
            thinking: boolean;
        }

        const processedSessions: ProcessedSession[] = [];

        for (const session of sessions) {
            logger.debug(`\n=== Processing session ${session.id} ===`);
            logger.debug(`Has dataEncryptionKey: ${!!session.dataEncryptionKey}`);
            logger.debug(`Has metadata: ${!!session.metadata}`);

            let metadata: Metadata = {};
            let agentState: AgentState = {};

            // Determine the encryption key to use
            let encryptionKey: Uint8Array | null = null;
            let encryptionVariant: 'legacy' | 'dataKey' = 'dataKey';

            if (session.dataEncryptionKey) {
                logger.debug(`Session has dataEncryptionKey, attempting to decrypt...`);
                encryptionKey = decryptDataEncryptionKey(session.dataEncryptionKey, credentials);
                if (!encryptionKey) {
                    logger.debug(`Failed to decrypt dataEncryptionKey for session ${session.id}`);
                } else {
                    logger.debug(`Successfully decrypted dataEncryptionKey`);
                }
            } else if (credentials.encryption.type === 'dataKey') {
                logger.debug(`Using machineKey directly for CLI session`);
                encryptionKey = credentials.encryption.machineKey;
            } else {
                logger.debug(`Using legacy secret key`);
                encryptionKey = credentials.encryption.secret;
                encryptionVariant = 'legacy';
            }

            // Decrypt metadata if present and we have a key
            if (session.metadata && encryptionKey) {
                logger.debug(`Attempting to decrypt metadata...`);
                try {
                    const metadataBytes = decodeBase64(session.metadata);
                    const decrypted = decrypt(encryptionKey, encryptionVariant, metadataBytes);
                    if (decrypted) {
                        logger.debug(`Successfully decrypted metadata:`, JSON.stringify(decrypted));
                        metadata = decrypted;
                    }
                } catch (error) {
                    logger.debug(`Failed to decrypt metadata for session ${session.id}:`, error);
                }
            }

            // Decrypt agent state if present and we have a key
            if (session.agentState && encryptionKey) {
                try {
                    const decrypted = decrypt(encryptionKey, encryptionVariant, decodeBase64(session.agentState));
                    if (decrypted) {
                        agentState = decrypted;
                    }
                } catch (error) {
                    logger.debug(`Failed to decrypt agent state for session ${session.id}:`, error);
                }
            }

            // Compute title
            let title = '(Untitled)';
            if (metadata.summary?.text) {
                title = metadata.summary.text;
            } else if (metadata.path) {
                const segments = metadata.path.split('/').filter(Boolean);
                if (segments.length > 0) {
                    title = segments[segments.length - 1];
                }
            }

            // Get working directory
            let workingDir = metadata.path || '(Unknown)';
            if (metadata.claudeSessionId && metadata.path) {
                workingDir = getCurrentWorkingDirectory(metadata.claudeSessionId, metadata.path);
            }

            processedSessions.push({
                session,
                metadata,
                agentState,
                encryptionKey,
                encryptionVariant,
                title,
                host: metadata.host || '(Unknown)',
                workingDir,
                thinking: !!agentState.thinking
            });
        }

        // Apply filters
        let filteredSessions = processedSessions;

        // Filter by session ID (prefix match)
        if (options.sessionId) {
            const idFilter = options.sessionId.toLowerCase();
            filteredSessions = filteredSessions.filter(s =>
                s.session.id.toLowerCase().startsWith(idFilter)
            );
        }

        // Filter by title (case-insensitive substring match)
        if (options.titleFilter) {
            const titleFilter = options.titleFilter.toLowerCase();
            filteredSessions = filteredSessions.filter(s =>
                s.title.toLowerCase().includes(titleFilter)
            );
        }

        if (filteredSessions.length === 0) {
            if (options.sessionId || options.titleFilter) {
                console.log('No sessions match the specified filters.');
            } else {
                console.log('No active sessions found.');
            }
            return;
        }

        // Determine if we need separators (multiple sessions with messages)
        const showMessages = options.recentMsgs && options.recentMsgs > 0;
        const needsSeparators = showMessages && filteredSessions.length > 1;
        const indent = needsSeparators ? '    ' : '';

        console.log(`\nActive Sessions (${filteredSessions.length}):\n`);

        // Display each session
        for (let i = 0; i < filteredSessions.length; i++) {
            const { session, encryptionKey, encryptionVariant, title, host, workingDir, thinking } = filteredSessions[i];

            // Print separator for multi-session output with messages
            if (needsSeparators && i > 0) {
                console.log('\n' + '═'.repeat(70) + '\n');
            }

            const thinkingStatus = thinking ? '🤔 Thinking' : '💤 Idle';

            console.log(`${indent}ID: ${session.id}`);
            console.log(`${indent}Title: ${title}`);
            console.log(`${indent}Working Directory: ${workingDir}`);
            console.log(`${indent}Host: ${host}`);
            console.log(`${indent}Status: ${thinkingStatus}`);
            console.log(`${indent}Last Active: ${formatTimeAgo(session.activeAt)}`);

            // Fetch and display recent messages if requested
            if (showMessages && encryptionKey) {
                console.log(`${indent}Recent Messages:`);
                const messages = await fetchSessionMessages(
                    session.id,
                    credentials,
                    encryptionKey,
                    encryptionVariant,
                    options.recentMsgs!
                );

                const displayableMessages = messages.filter(shouldDisplayMessage);
                const msgLen = options.msgLen ?? 200;
                if (displayableMessages.length === 0) {
                    console.log(`${indent}    (no messages)`);
                } else {
                    for (const msg of displayableMessages) {
                        console.log(formatMessage(msg, indent + '    ', msgLen));
                    }
                }
            }

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
