/**
 * Parsers for special commands that require dedicated remote session handling
 */

export interface CompactCommandResult {
    isCompact: boolean;
    originalMessage: string;
}

export interface ClearCommandResult {
    isClear: boolean;
}

export interface HappyStatusCommandResult {
    isHappyStatus: boolean;
    echoMessage?: string;
}

export interface SpecialCommandResult {
    type: 'compact' | 'clear' | 'happy-status' | null;
    originalMessage?: string;
    echoMessage?: string;
}

/**
 * Parse /compact command
 * Matches messages starting with "/compact " or exactly "/compact"
 */
export function parseCompact(message: string): CompactCommandResult {
    const trimmed = message.trim();
    
    if (trimmed === '/compact') {
        return {
            isCompact: true,
            originalMessage: trimmed
        };
    }
    
    if (trimmed.startsWith('/compact ')) {
        return {
            isCompact: true,
            originalMessage: trimmed
        };
    }
    
    return {
        isCompact: false,
        originalMessage: message
    };
}

/**
 * Parse /clear command
 * Only matches exactly "/clear"
 */
export function parseClear(message: string): ClearCommandResult {
    const trimmed = message.trim();

    return {
        isClear: trimmed === '/clear'
    };
}

/**
 * Parse /happy-status command
 * Used for testing the message flow without calling Claude/Anthropic API
 * Format: "/happy-status" or "/happy-status some echo message"
 */
export function parseHappyStatus(message: string): HappyStatusCommandResult {
    const trimmed = message.trim();

    if (trimmed === '/happy-status') {
        return {
            isHappyStatus: true
        };
    }

    if (trimmed.startsWith('/happy-status ')) {
        return {
            isHappyStatus: true,
            echoMessage: trimmed.substring('/happy-status '.length).trim()
        };
    }

    return {
        isHappyStatus: false
    };
}

/**
 * Unified parser for special commands
 * Returns the type of command and original message if applicable
 */
export function parseSpecialCommand(message: string): SpecialCommandResult {
    const compactResult = parseCompact(message);
    if (compactResult.isCompact) {
        return {
            type: 'compact',
            originalMessage: compactResult.originalMessage
        };
    }

    const clearResult = parseClear(message);
    if (clearResult.isClear) {
        return {
            type: 'clear'
        };
    }

    const happyStatusResult = parseHappyStatus(message);
    if (happyStatusResult.isHappyStatus) {
        return {
            type: 'happy-status',
            echoMessage: happyStatusResult.echoMessage
        };
    }

    return {
        type: null
    };
}