/**
 * Direnv environment loading utility
 *
 * Loads environment variables from direnv for a given directory.
 * Falls back gracefully if direnv is not available or .envrc doesn't exist.
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { logger } from '@/ui/logger';

const execAsync = promisify(exec);

/** Cache direnv availability check */
let direnvAvailable: boolean | null = null;

/**
 * Check if direnv is available on the system
 */
async function isDirenvAvailable(): Promise<boolean> {
    if (direnvAvailable !== null) {
        return direnvAvailable;
    }

    try {
        await execAsync('direnv version', { timeout: 5000 });
        direnvAvailable = true;
        logger.debug('[direnv] direnv is available');
    } catch {
        direnvAvailable = false;
        logger.debug('[direnv] direnv is not available');
    }

    return direnvAvailable;
}

/**
 * Find .envrc file by walking up directory tree
 * @param startDir - Directory to start searching from
 * @returns Directory containing .envrc, or null if not found
 */
function findEnvrcDirectory(startDir: string): string | null {
    let dir = startDir;
    const root = '/';

    while (dir !== root) {
        const envrcPath = join(dir, '.envrc');
        if (existsSync(envrcPath)) {
            logger.debug(`[direnv] Found .envrc at: ${envrcPath}`);
            return dir;
        }
        const parent = dirname(dir);
        if (parent === dir) {
            break; // Reached filesystem root
        }
        dir = parent;
    }

    logger.debug(`[direnv] No .envrc found in directory tree for: ${startDir}`);
    return null;
}

/**
 * Load environment variables from direnv for a given directory
 *
 * @param cwd - The working directory to load environment for
 * @returns Record of environment variables from direnv (empty object if unavailable)
 *
 * @example
 * ```typescript
 * const direnvVars = await loadDirenvEnvironment('/path/to/project');
 * const mergedEnv = { ...process.env, ...direnvVars };
 * ```
 */
export async function loadDirenvEnvironment(
    cwd: string
): Promise<Record<string, string>> {
    // Check if direnv is available
    if (!(await isDirenvAvailable())) {
        return {};
    }

    // Check for .envrc in directory tree
    const envrcDir = findEnvrcDirectory(cwd);
    if (!envrcDir) {
        return {};
    }

    try {
        logger.debug(`[direnv] Loading environment for: ${cwd}`);

        // Run direnv export json to get environment variables
        // We run it in the target directory so direnv resolves relative to that
        const { stdout, stderr } = await execAsync('direnv export json', {
            cwd,
            timeout: 10000, // 10 second timeout
            env: {
                ...process.env,
                // Ensure direnv doesn't prompt for allowance interactively
                DIRENV_LOG_FORMAT: '',
            }
        });

        if (stderr) {
            logger.debug(`[direnv] stderr: ${stderr}`);
        }

        const trimmed = stdout.trim();
        if (!trimmed) {
            logger.debug('[direnv] No environment changes from direnv');
            return {};
        }

        const direnvVars = JSON.parse(trimmed) as Record<string, string>;
        const varCount = Object.keys(direnvVars).length;
        logger.debug(`[direnv] Loaded ${varCount} environment variables`);

        return direnvVars;
    } catch (error) {
        // direnv export can fail for various reasons:
        // - .envrc not allowed (needs `direnv allow`)
        // - Syntax error in .envrc
        // - Timeout
        // We fail gracefully and return empty object
        if (error instanceof Error) {
            logger.debug(`[direnv] Failed to load environment: ${error.message}`);

            // Check if it's a "not allowed" error and provide helpful message
            if (error.message.includes('is blocked')) {
                logger.debug('[direnv] Hint: Run "direnv allow" in the project directory to allow the .envrc');
            }
        }

        return {};
    }
}

/**
 * Load direnv environment and merge with existing environment
 *
 * @param cwd - The working directory to load environment for
 * @param existingEnv - Existing environment variables (defaults to process.env)
 * @param overrideEnv - Additional environment variables that take priority
 * @returns Merged environment record
 *
 * @example
 * ```typescript
 * const env = await loadAndMergeEnvironment('/path/to/project', process.env, { MY_VAR: 'value' });
 * ```
 */
export async function loadAndMergeEnvironment(
    cwd: string,
    existingEnv: Record<string, string | undefined> = process.env,
    overrideEnv: Record<string, string> = {}
): Promise<Record<string, string>> {
    const direnvVars = await loadDirenvEnvironment(cwd);

    // Merge order: existingEnv < direnvVars < overrideEnv
    // This means:
    // 1. Start with existing environment
    // 2. direnv variables override existing
    // 3. Explicit overrides take final priority
    const merged: Record<string, string> = {};

    // Add existing env (filter out undefined values)
    for (const [key, value] of Object.entries(existingEnv)) {
        if (value !== undefined) {
            merged[key] = value;
        }
    }

    // Add direnv vars (overrides existing)
    for (const [key, value] of Object.entries(direnvVars)) {
        merged[key] = value;
    }

    // Add override vars (highest priority)
    for (const [key, value] of Object.entries(overrideEnv)) {
        merged[key] = value;
    }

    return merged;
}
