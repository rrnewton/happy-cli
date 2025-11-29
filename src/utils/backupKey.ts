/**
 * Backup key formatting utilities
 * Formats and parses secret keys in the same way as the mobile/web client for compatibility
 */

// Base32 alphabet (RFC 4648) - excludes confusing characters
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function bytesToBase32(bytes: Uint8Array): string {
    let result = '';
    let buffer = 0;
    let bufferLength = 0;

    for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bufferLength += 8;

        while (bufferLength >= 5) {
            bufferLength -= 5;
            result += BASE32_ALPHABET[(buffer >> bufferLength) & 0x1f];
        }
    }

    // Handle remaining bits
    if (bufferLength > 0) {
        result += BASE32_ALPHABET[(buffer << (5 - bufferLength)) & 0x1f];
    }

    return result;
}

function base32ToBytes(base32: string): Uint8Array {
    // Normalize the input:
    // 1. Convert to uppercase
    // 2. Replace common mistakes: 0->O, 1->I, 8->B
    // 3. Remove all non-base32 characters (spaces, dashes, etc)
    let normalized = base32.toUpperCase()
        .replace(/0/g, 'O')  // Zero to O
        .replace(/1/g, 'I')  // One to I
        .replace(/8/g, 'B')  // Eight to B
        .replace(/9/g, 'G'); // Nine to G (arbitrary but consistent)

    // Remove any non-base32 characters
    const cleaned = normalized.replace(/[^A-Z2-7]/g, '');

    // Check if we have any content left
    if (cleaned.length === 0) {
        throw new Error('No valid characters found in backup key');
    }

    const bytes: number[] = [];
    let buffer = 0;
    let bufferLength = 0;

    for (const char of cleaned) {
        const value = BASE32_ALPHABET.indexOf(char);
        if (value === -1) {
            throw new Error('Invalid base32 character in backup key');
        }

        buffer = (buffer << 5) | value;
        bufferLength += 5;

        if (bufferLength >= 8) {
            bufferLength -= 8;
            bytes.push((buffer >> bufferLength) & 0xff);
        }
    }

    return new Uint8Array(bytes);
}

/**
 * Formats a secret key for display in a user-friendly format matching mobile client
 * @param secretBytes - 32-byte secret key as Uint8Array
 * @returns Formatted string like "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
 */
export function formatSecretKeyForBackup(secretBytes: Uint8Array): string {
    // Convert to base32
    const base32 = bytesToBase32(secretBytes);

    // Split into groups of 5 characters
    const groups: string[] = [];
    for (let i = 0; i < base32.length; i += 5) {
        groups.push(base32.slice(i, i + 5));
    }

    // Join with dashes
    // 32 bytes = 256 bits = 52 base32 chars (51.2 rounded up)
    // That's approximately 11 groups of 5 chars
    return groups.join('-');
}

/**
 * Parses a backup key (formatted or raw base32) back to bytes
 * @param backupKey - Formatted string like "XXXXX-XXXXX-..." or raw base32 string
 * @returns 32-byte secret key as Uint8Array
 * @throws Error if the key is invalid or doesn't decode to 32 bytes
 */
export function parseBackupKey(backupKey: string): Uint8Array {
    const trimmed = backupKey.trim();

    if (trimmed.length === 0) {
        throw new Error('Backup key cannot be empty');
    }

    const bytes = base32ToBytes(trimmed);

    if (bytes.length !== 32) {
        throw new Error(`Invalid backup key: expected 32 bytes, got ${bytes.length}`);
    }

    return bytes;
}