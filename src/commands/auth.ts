import chalk from 'chalk';
import { readCredentials, clearCredentials, clearMachineId, readSettings, Credentials, writeCredentialsLegacy, updateSettings } from '@/persistence';
import { authAndSetupMachineIfNeeded } from '@/ui/auth';
import { configuration } from '@/configuration';
import { existsSync, rmSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { stopDaemon, checkIfDaemonRunningAndCleanupStaleState } from '@/daemon/controlClient';
import { logger } from '@/ui/logger';
import os from 'node:os';
import { deriveKey } from '@/utils/deriveKey';
import { encodeHex } from '@/utils/hex';
import { parseBackupKey } from '@/utils/backupKey';
import { authGetToken } from '@/api/auth';
import { randomUUID } from 'node:crypto';
import axios from 'axios';

export async function handleAuthCommand(args: string[]): Promise<void> {
  const subcommand = args[0];

  if (!subcommand || subcommand === 'help' || subcommand === '--help' || subcommand === '-h') {
    showAuthHelp();
    return;
  }

  switch (subcommand) {
    case 'login':
      await handleAuthLogin(args.slice(1));
      break;
    case 'logout':
      await handleAuthLogout();
      break;
    // case 'backup':
    //   await handleAuthShowBackup();
    //   break;
    case 'status':
      await handleAuthStatus();
      break;
    case 'account':
      // Deprecated: merged into 'status'
      console.log(chalk.yellow('Note: "auth account" is now part of "auth status"'));
      await handleAuthStatus();
      break;
    default:
      console.error(chalk.red(`Unknown auth subcommand: ${subcommand}`));
      showAuthHelp();
      process.exit(1);
  }
}

function showAuthHelp(): void {
  console.log(`
${chalk.bold('happy auth')} - Authentication management

${chalk.bold('Usage:')}
  happy auth login [options]    Authenticate with Happy
  happy auth logout             Remove authentication and machine data
  happy auth status             Show authentication and account status
  happy auth help               Show this help message

${chalk.bold('Login Options:')}
  --backup-key <KEY>   Login using backup key from webapp (XXXXX-XXXXX-...)
  --force              Clear credentials, machine ID, and stop daemon before re-auth

${chalk.bold('Examples:')}
  happy auth login --backup-key "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-Z2345-67ABC-DEFGH-IJKLM-NOPQR-S"
`);
}

async function handleAuthLogin(args: string[]): Promise<void> {
  const forceAuth = args.includes('--force') || args.includes('-f');

  // Parse --backup-key argument
  const backupKeyIndex = args.findIndex(arg => arg === '--backup-key' || arg === '-k');
  const backupKey = backupKeyIndex !== -1 ? args[backupKeyIndex + 1] : null;

  if (forceAuth) {
    // As per user's request: "--force-auth will clear credentials, clear machine ID, stop daemon"
    console.log(chalk.yellow('Force authentication requested.'));
    console.log(chalk.gray('This will:'));
    console.log(chalk.gray('  • Clear existing credentials'));
    console.log(chalk.gray('  • Clear machine ID'));
    console.log(chalk.gray('  • Stop daemon if running'));
    console.log(chalk.gray('  • Re-authenticate and register machine\n'));

    // Stop daemon if running
    try {
      logger.debug('Stopping daemon for force auth...');
      await stopDaemon();
      console.log(chalk.gray('✓ Stopped daemon'));
    } catch (error) {
      logger.debug('Daemon was not running or failed to stop:', error);
    }

    // Clear credentials
    await clearCredentials();
    console.log(chalk.gray('✓ Cleared credentials'));

    // Clear machine ID
    await clearMachineId();
    console.log(chalk.gray('✓ Cleared machine ID'));

    console.log('');
  }

  // Handle backup key login
  if (backupKey) {
    await handleBackupKeyLogin(backupKey);
    return;
  }

  // Check if already authenticated (if not forcing)
  if (!forceAuth) {
    const existingCreds = await readCredentials();
    const settings = await readSettings();

    if (existingCreds && settings?.machineId) {
      console.log(chalk.green('✓ Already authenticated'));
      console.log(chalk.gray(`  Machine ID: ${settings.machineId}`));
      console.log(chalk.gray(`  Host: ${os.hostname()}`));
      console.log(chalk.gray(`  Use 'happy auth login --force' to re-authenticate`));
      return;
    } else if (existingCreds && !settings?.machineId) {
      console.log(chalk.yellow('⚠️  Credentials exist but machine ID is missing'));
      console.log(chalk.gray('  This can happen if --auth flag was used previously'));
      console.log(chalk.gray('  Fixing by setting up machine...\n'));
    }
  }

  // Perform authentication and machine setup
  // "Finally we'll run the auth and setup machine if needed"
  try {
    const result = await authAndSetupMachineIfNeeded();
    console.log(chalk.green('\n✓ Authentication successful'));
    console.log(chalk.gray(`  Machine ID: ${result.machineId}`));
  } catch (error) {
    console.error(chalk.red('Authentication failed:'), error instanceof Error ? error.message : 'Unknown error');
    process.exit(1);
  }
}

/**
 * Handle login using a backup key from the webapp
 * This allows logging into the same account on multiple CLI instances
 */
async function handleBackupKeyLogin(backupKey: string): Promise<void> {
  console.log(chalk.blue('Logging in with backup key...\n'));

  try {
    // Parse the backup key to get the raw secret bytes
    const secretBytes = parseBackupKey(backupKey);
    console.log(chalk.gray('✓ Parsed backup key'));

    // Authenticate with the server to get a token
    console.log(chalk.gray('  Authenticating with server...'));
    const token = await authGetToken(secretBytes);
    console.log(chalk.gray('✓ Received authentication token'));

    // Save credentials (using legacy format since we have the master secret)
    await writeCredentialsLegacy({ secret: secretBytes, token });
    console.log(chalk.gray('✓ Saved credentials'));

    // Generate a machine ID
    const settings = await updateSettings(async s => ({
      ...s,
      machineId: randomUUID()
    }));
    console.log(chalk.gray('✓ Generated machine ID'));

    console.log(chalk.green('\n✓ Authentication successful'));
    console.log(chalk.gray(`  Machine ID: ${settings.machineId}`));
    console.log(chalk.gray(`  Host: ${os.hostname()}`));
    console.log(chalk.gray(`  Server: ${configuration.serverUrl}`));
  } catch (error) {
    console.error(chalk.red('Authentication failed:'), error instanceof Error ? error.message : 'Unknown error');
    process.exit(1);
  }
}

async function handleAuthLogout(): Promise<void> {
  // "auth logout will essentially clear the private key that originally came from the phone"
  const happyDir = configuration.happyHomeDir;

  // Check if authenticated
  const credentials = await readCredentials();
  if (!credentials) {
    console.log(chalk.yellow('Not currently authenticated'));
    return;
  }

  console.log(chalk.blue('This will log you out of Happy'));
  console.log(chalk.yellow('⚠️  You will need to re-authenticate to use Happy again'));

  // Ask for confirmation
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const answer = await new Promise<string>((resolve) => {
    rl.question(chalk.yellow('Are you sure you want to log out? (y/N): '), resolve);
  });

  rl.close();

  if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
    try {
      // Stop daemon if running
      try {
        await stopDaemon();
        console.log(chalk.gray('Stopped daemon'));
      } catch { }

      // Remove entire happy directory (as current logout does)
      if (existsSync(happyDir)) {
        rmSync(happyDir, { recursive: true, force: true });
      }

      console.log(chalk.green('✓ Successfully logged out'));
      console.log(chalk.gray('  Run "happy auth login" to authenticate again'));
    } catch (error) {
      throw new Error(`Failed to logout: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  } else {
    console.log(chalk.blue('Logout cancelled'));
  }
}

// async function handleAuthShowBackup(): Promise<void> {
//   const credentials = await readCredentials();
//   const settings = await readSettings();

//   if (!credentials) {
//     console.log(chalk.yellow('Not authenticated'));
//     console.log(chalk.gray('Run "happy auth login" to authenticate first'));
//     return;
//   }

//   // Format the backup key exactly like the mobile client expects
//   // Mobile client uses formatSecretKeyForBackup which converts to base32 with dashes
//   const formattedBackupKey = formatSecretKeyForBackup(credentials.encryption.secret);

//   console.log(chalk.bold('\n📱 Backup Key\n'));

//   // Display in the format XXXXX-XXXXX-XXXXX-... that mobile expects
//   console.log(chalk.cyan('Your backup key:'));
//   console.log(chalk.bold(formattedBackupKey));
//   console.log('');

//   console.log(chalk.cyan('Machine Information:'));
//   console.log(`  Machine ID: ${settings?.machineId || 'not set'}`);
//   console.log(`  Host: ${os.hostname()}`);
//   console.log('');

//   console.log(chalk.bold('How to use this backup key:'));
//   console.log(chalk.gray('• In Happy mobile app: Go to restore/link device and enter this key'));
//   console.log(chalk.gray('• This key format matches what the mobile app expects'));
//   console.log(chalk.gray('• You can type it with or without dashes - the app will normalize it'));
//   console.log(chalk.gray('• Common typos (0→O, 1→I) are automatically corrected'));
//   console.log('');

//   console.log(chalk.yellow('⚠️  Keep this key secure - it provides full access to your account'));
// }

/**
 * Parse the user ID (sub claim) from a JWT token
 */
function parseTokenSub(token: string): string {
  const [, payload] = token.split('.');
  const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  if (typeof decoded.sub !== 'string') {
    throw new Error('Invalid token: missing sub claim');
  }
  return decoded.sub;
}

/**
 * Result of validating account with the server
 */
interface AccountValidationResult {
  valid: boolean;
  profile?: { username: string | null; firstName: string | null; lastName: string | null };
  error?: 'network_error' | 'account_not_found' | 'auth_error' | 'server_error';
  errorMessage?: string;
}

/**
 * Validate that the account exists on the server and fetch profile
 * This is a CRITICAL check - we must distinguish between:
 * - Account exists and is valid
 * - Account does NOT exist (credentials are stale/invalid)
 * - Network/server errors (temporary issues)
 */
async function validateAccountWithServer(token: string): Promise<AccountValidationResult> {
  try {
    const response = await axios.get(`${configuration.serverUrl}/v1/account/profile`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    return {
      valid: true,
      profile: {
        username: response.data.username,
        firstName: response.data.firstName,
        lastName: response.data.lastName
      }
    };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status;

      // 401/403 - Authentication/authorization error (token invalid or account doesn't exist)
      if (status === 401 || status === 403) {
        return {
          valid: false,
          error: 'auth_error',
          errorMessage: 'Authentication failed - your credentials may be invalid or expired'
        };
      }

      // 404 or 500 with P2025 (Prisma record not found) - Account doesn't exist
      // The server returns 500 with Prisma errors when account is missing
      if (status === 404 || status === 500) {
        const responseData = error.response?.data;
        const isAccountNotFound =
          status === 404 ||
          (responseData?.errorCode === 'P2025') ||
          (typeof responseData === 'string' && responseData.includes('P2025')) ||
          (responseData?.message?.includes('not found'));

        if (isAccountNotFound || status === 500) {
          return {
            valid: false,
            error: 'account_not_found',
            errorMessage: 'Account not found on server - your credentials are stale. Run "happy auth logout" and re-authenticate.'
          };
        }

        return {
          valid: false,
          error: 'server_error',
          errorMessage: `Server error (${status}): ${error.message}`
        };
      }

      // Network errors (ECONNREFUSED, ETIMEDOUT, etc.)
      if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND') {
        return {
          valid: false,
          error: 'network_error',
          errorMessage: `Cannot reach server at ${configuration.serverUrl}: ${error.code}`
        };
      }
    }

    // Generic network/unknown error
    logger.debug('Failed to validate account:', error);
    return {
      valid: false,
      error: 'network_error',
      errorMessage: error instanceof Error ? error.message : 'Unknown error connecting to server'
    };
  }
}

async function handleAuthStatus(): Promise<void> {
  const credentials = await readCredentials();
  const settings = await readSettings();

  console.log(chalk.bold('\nAuthentication Status\n'));

  // Show happy home directory
  console.log(chalk.gray(`  Happy home: ${configuration.happyHomeDir}`));
  console.log(chalk.gray(`  Server: ${configuration.serverUrl}`));
  console.log('');

  if (!credentials) {
    console.log(chalk.red('✗ Not authenticated'));
    console.log(chalk.gray('  Run "happy auth login" to authenticate'));
    return;
  }

  // CRITICAL: Validate that the account actually exists on the server
  // This catches the case where credentials are stale (e.g., database was wiped)
  console.log(chalk.gray('Validating credentials with server...'));
  const validation = await validateAccountWithServer(credentials.token);

  if (!validation.valid) {
    // Account validation failed - this is a CRITICAL error
    if (validation.error === 'account_not_found' || validation.error === 'auth_error') {
      console.log(chalk.red.bold('\n❌ AUTHENTICATION INVALID'));
      console.log(chalk.red(`   ${validation.errorMessage}`));
      console.log('');
      console.log(chalk.yellow('Your local credentials do not match any account on the server.'));
      console.log(chalk.yellow('This can happen if:'));
      console.log(chalk.gray('  • The database was reset or migrated'));
      console.log(chalk.gray('  • You are pointing to a different server'));
      console.log(chalk.gray('  • Your account was deleted'));
      console.log('');
      console.log(chalk.cyan('To fix this, run:'));
      console.log(chalk.white('  happy auth logout'));
      console.log(chalk.white('  happy auth login'));
      console.log('');
      process.exit(1);
    } else if (validation.error === 'network_error') {
      console.log(chalk.yellow(`\n⚠️  Cannot verify credentials: ${validation.errorMessage}`));
      console.log(chalk.gray('  Server may be unreachable. Showing local credentials status only.\n'));
      // Continue to show local status, but warn user
    } else {
      console.log(chalk.yellow(`\n⚠️  Server error: ${validation.errorMessage}`));
      console.log(chalk.gray('  Showing local credentials status only.\n'));
    }
  }

  // Only show "Authenticated" if we actually validated with the server
  if (validation.valid) {
    console.log(chalk.green('✓ Authenticated (verified with server)'));

    // Show profile info from validated response
    if (validation.profile) {
      if (validation.profile.username) {
        console.log(chalk.gray(`  Username: ${validation.profile.username}`));
      }
      const displayName = [validation.profile.firstName, validation.profile.lastName].filter(Boolean).join(' ');
      if (displayName) {
        console.log(chalk.gray(`  Name: ${displayName}`));
      }
    }
  } else if (validation.error === 'network_error') {
    // Network error - show local state with warning
    console.log(chalk.yellow('⚠️  Credentials found (unverified - server unreachable)'));
  }

  // Public ID from JWT
  const publicId = parseTokenSub(credentials.token);
  console.log(chalk.gray(`  Public ID: ${publicId}`));

  // Anonymous ID - only for legacy credentials
  if (credentials.encryption.type === 'legacy') {
    const masterSecret = credentials.encryption.secret;
    const analyticsKey = await deriveKey(masterSecret, 'Happy Coder', ['analytics', 'id']);
    const anonId = encodeHex(analyticsKey).slice(0, 16).toLowerCase();
    console.log(chalk.gray(`  Anonymous ID: ${anonId}`));
  }

  // Machine status
  if (settings?.machineId) {
    console.log(chalk.green('✓ Machine registered'));
    console.log(chalk.gray(`  Machine ID: ${settings.machineId}`));
    console.log(chalk.gray(`  Host: ${os.hostname()}`));
  } else {
    console.log(chalk.yellow('⚠️  Machine not registered'));
    console.log(chalk.gray('  Run "happy auth login --force" to fix this'));
  }

  // Daemon status
  try {
    const running = await checkIfDaemonRunningAndCleanupStaleState();
    if (running) {
      console.log(chalk.green('✓ Daemon running'));
    } else {
      console.log(chalk.gray('✗ Daemon not running'));
    }
  } catch {
    console.log(chalk.gray('✗ Daemon not running'));
  }
}

