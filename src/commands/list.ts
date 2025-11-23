/**
 * List active sessions command
 *
 * Fetches active sessions from the server and displays them in a user-friendly format.
 */

import { configuration } from '@/configuration';
import { Credentials } from '@/persistence';
import axios from 'axios';
import { decrypt, decodeBase64 } from '@/api/encryption';
import { logger } from '@/ui/logger';
import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

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
}

interface Metadata {
    path?: string;
    title?: string;
    host?: string;
    [key: string]: any;
}

interface AgentState {
    thinking?: boolean;
    [key: string]: any;
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
            let metadata: Metadata = {};
            let agentState: AgentState = {};

            // Decrypt metadata if present
            if (session.metadata) {
                try {
                    const key = credentials.encryption.type === 'legacy'
                        ? credentials.encryption.secret
                        : credentials.encryption.machineKey;
                    const decrypted = decrypt(
                        key,
                        credentials.encryption.type,
                        decodeBase64(session.metadata)
                    );
                    if (decrypted) {
                        metadata = decrypted;
                    }
                } catch (error) {
                    logger.debug(`Failed to decrypt metadata for session ${session.id}:`, error);
                }
            }

            // Decrypt agent state if present
            if (session.agentState) {
                try {
                    const key = credentials.encryption.type === 'legacy'
                        ? credentials.encryption.secret
                        : credentials.encryption.machineKey;
                    const decrypted = decrypt(
                        key,
                        credentials.encryption.type,
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
            const title = metadata.title || '(Untitled)';
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
