/**
 * Send prompt to session command
 *
 * Sends a prompt to a running Claude session and waits for the response.
 */

import { configuration } from '@/configuration';
import { Credentials } from '@/persistence';
import axios from 'axios';
import { decrypt, encrypt, decodeBase64, encodeBase64 } from '@/api/encryption';
import { logger } from '@/ui/logger';
import { io, Socket } from 'socket.io-client';
import { ServerToClientEvents, ClientToServerEvents, Update } from '@/api/types';

interface SessionResponse {
    id: string;
    metadata: string | null;
    metadataVersion: number;
    agentState: string | null;
    agentStateVersion: number;
    active: boolean;
    lastActiveAt: string;
    createdAt: string;
    updatedAt: string;
}

interface AgentState {
    thinking?: boolean;
    [key: string]: any;
}

interface MessageContent {
    role: 'user';
    content: {
        type: 'text';
        text: string;
    };
    meta: {
        sentFrom: 'cli';
    };
}

/**
 * Send a prompt to a session and wait for completion
 */
export async function promptSession(credentials: Credentials, sessionId: string, promptText: string): Promise<void> {
    try {
        const serverUrl = configuration.serverUrl;

        // Fetch session from server
        const response = await axios.get<{ sessions: SessionResponse[] }>(`${serverUrl}/v2/sessions/active`, {
            headers: {
                'Authorization': `Bearer ${credentials.token}`
            }
        });

        const session = response.data.sessions.find(s => s.id === sessionId);
        if (!session) {
            console.error(`Session ${sessionId} not found or not active.`);
            process.exit(1);
        }

        // Check if Claude is already thinking
        let agentState: AgentState = {};
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
                logger.debug(`Failed to decrypt agent state for session ${sessionId}:`, error);
            }
        }

        if (agentState.thinking) {
            console.error('Claude is already working on a task. Please wait for it to finish.');
            process.exit(1);
        }

        // Connect to WebSocket
        const wsUrl = serverUrl.replace(/^http/, 'ws');
        const socket: Socket<ServerToClientEvents, ClientToServerEvents> = io(wsUrl, {
            path: '/v1/updates',
            auth: {
                token: credentials.token,
                clientType: 'session-scoped',
                sessionId: sessionId
            },
            transports: ['websocket', 'polling']
        });

        let isThinking = false;
        let hasStartedThinking = false;
        let completed = false;
        let hasError = false;

        // Handle connection
        await new Promise<void>((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Error('Connection timeout'));
            }, 10000);

            socket.on('connect', () => {
                clearTimeout(timeout);
                logger.debug(`Connected to WebSocket for session ${sessionId}`);
                resolve();
            });

            socket.on('connect_error', (error) => {
                clearTimeout(timeout);
                reject(error);
            });
        });

        // Handle updates (messages from Claude)
        socket.on('update', (data: Update) => {
            logger.debugLargeJson('[prompt] Received update:', data);

            if (data.body.t === 'new-message') {
                try {
                    // Decrypt message content
                    const key = credentials.encryption.type === 'legacy'
                        ? credentials.encryption.secret
                        : credentials.encryption.machineKey;
                    const content = decrypt(
                        key,
                        credentials.encryption.type,
                        decodeBase64(data.body.message.content.c)
                    );

                    if (!content) {
                        logger.debug('Failed to decrypt message content');
                        return;
                    }

                    // Display agent output messages
                    if (content.role === 'agent' && content.content?.type === 'output') {
                        const output = content.content.data;
                        // Format and display Claude's output based on message type
                        if (output.type === 'user' && output.message?.content) {
                            // User message - could be tool result with is_error
                            console.log('[User]:', output.message.content);
                            // Check for error in tool results
                            if (Array.isArray(output.message.content)) {
                                for (const block of output.message.content) {
                                    if (block.is_error === true) {
                                        hasError = true;
                                        logger.debug('[prompt] Detected error in tool result');
                                    }
                                }
                            }
                        } else if (output.type === 'assistant' && output.message?.content) {
                            // Assistant message - could be text or tool use
                            if (Array.isArray(output.message.content)) {
                                for (const block of output.message.content) {
                                    if (block.type === 'text') {
                                        console.log(block.text);
                                    } else if (block.type === 'tool_use') {
                                        console.log(`\n[Tool: ${block.name}]`);
                                    }
                                }
                            }
                        }
                    }
                } catch (error) {
                    logger.debug('Failed to decrypt or process message:', error);
                }
            } else if (data.body.t === 'update-session' && data.body.agentState) {
                // Session state update - check thinking status
                try {
                    if (data.body.agentState.value) {
                        const key = credentials.encryption.type === 'legacy'
                            ? credentials.encryption.secret
                            : credentials.encryption.machineKey;
                        const updatedState = decrypt(
                            key,
                            credentials.encryption.type,
                            decodeBase64(data.body.agentState.value)
                        );
                        if (updatedState) {
                            logger.debug(`[prompt] Agent state updated: thinking=${updatedState.thinking}`);
                        }
                    }
                } catch (error) {
                    logger.debug('Failed to decrypt agent state:', error);
                }
            }
        });

        // Handle ephemeral events (thinking status updates)
        socket.on('ephemeral', (data) => {
            if (data.type === 'activity' && data.id === sessionId) {
                logger.debug(`[prompt] Activity update: thinking=${data.thinking}, active=${data.active}`);

                if (data.thinking && !hasStartedThinking) {
                    hasStartedThinking = true;
                    console.log('[Claude is thinking...]');
                }

                isThinking = data.thinking;

                // If Claude has finished thinking and we've seen it start, we're done
                if (hasStartedThinking && !data.thinking) {
                    completed = true;
                }
            }
        });

        // Send the prompt message
        const messageContent: MessageContent = {
            role: 'user',
            content: {
                type: 'text',
                text: promptText
            },
            meta: {
                sentFrom: 'cli'
            }
        };

        const key = credentials.encryption.type === 'legacy'
            ? credentials.encryption.secret
            : credentials.encryption.machineKey;
        const encryptedMessage = encodeBase64(encrypt(
            key,
            credentials.encryption.type,
            messageContent
        ));

        logger.debug('[prompt] Sending message to session...');
        socket.emit('message', {
            sid: sessionId,
            message: encryptedMessage
        });

        console.log(`[Sent prompt to session ${sessionId}]`);

        // Wait for completion
        const checkInterval = setInterval(() => {
            if (completed) {
                clearInterval(checkInterval);
                socket.close();
                console.log('\n[Claude has finished]');
                // Exit with error code if any tool result had is_error: true
                process.exit(hasError ? 1 : 0);
            }
        }, 500);

        // Timeout after 5 minutes
        setTimeout(() => {
            clearInterval(checkInterval);
            socket.close();
            console.error('\nTimeout waiting for Claude to complete.');
            process.exit(1);
        }, 5 * 60 * 1000);

    } catch (error) {
        if (axios.isAxiosError(error)) {
            if (error.response?.status === 401) {
                console.error('Authentication failed. Please run `happy auth` to authenticate.');
            } else {
                console.error(`Failed to send prompt: ${error.response?.data?.message || error.message}`);
            }
        } else {
            console.error(`Failed to send prompt: ${error}`);
        }
        process.exit(1);
    }
}
