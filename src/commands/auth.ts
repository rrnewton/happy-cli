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
      await handleAuthAccount();
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
  happy auth status             Show authentication status
  happy auth account            Show account IDs (matches webapp Account page)
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

async function handleAuthStatus(): Promise<void> {
  const credentials = await readCredentials();
  const settings = await readSettings();

  console.log(chalk.bold('\nAuthentication Status\n'));

  if (!credentials) {
    console.log(chalk.red('✗ Not authenticated'));
    console.log(chalk.gray('  Run "happy auth login" to authenticate'));
    return;
  }

  console.log(chalk.green('✓ Authenticated'));

  // Token preview (first few chars for security)
  const tokenPreview = credentials.token.substring(0, 30) + '...';
  console.log(chalk.gray(`  Token: ${tokenPreview}`));

  // Machine status
  if (settings?.machineId) {
    console.log(chalk.green('✓ Machine registered'));
    console.log(chalk.gray(`  Machine ID: ${settings.machineId}`));
    console.log(chalk.gray(`  Host: ${os.hostname()}`));
  } else {
    console.log(chalk.yellow('⚠️  Machine not registered'));
    console.log(chalk.gray('  Run "happy auth login --force" to fix this'));
  }

  // Data location
  console.log(chalk.gray(`\n  Data directory: ${configuration.happyHomeDir}`));

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
 * Get the master secret from credentials for deriving anonymous ID
 */
function getMasterSecret(credentials: Credentials): Uint8Array {
  if (credentials.encryption.type === 'legacy') {
    return credentials.encryption.secret;
  } else {
    return credentials.encryption.dataKeySeed;
  }
}

/**
 * Show account IDs that match the webapp's Account page
 * This helps verify CLI and webapp are using the same account
 */
async function handleAuthAccount(): Promise<void> {
  const credentials = await readCredentials();

  if (!credentials) {
    console.log(chalk.red('✗ Not authenticated'));
    console.log(chalk.gray('  Run "happy auth login" to authenticate'));
    return;
  }

  console.log(chalk.bold('\nAccount Information\n'));

  // Public ID (server ID) - from JWT token's sub claim
  const publicId = parseTokenSub(credentials.token);
  console.log(`${chalk.cyan('Public ID:')}    ${publicId}`);

  // Anonymous ID - only available for legacy credentials
  // For dataKey credentials, the CLI receives contentDataKey (a public key),
  // not the original masterSecret, so we cannot derive the matching anonymous ID
  if (credentials.encryption.type === 'legacy') {
    const masterSecret = credentials.encryption.secret;
    const analyticsKey = await deriveKey(masterSecret, 'Happy Coder', ['analytics', 'id']);
    const anonId = encodeHex(analyticsKey).slice(0, 16).toLowerCase();
    console.log(`${chalk.cyan('Anonymous ID:')} ${anonId}`);
    console.log(chalk.gray('\nThese IDs should match what you see in the webapp under Settings > Account'));
  } else {
    console.log(`${chalk.cyan('Anonymous ID:')} ${chalk.yellow('N/A (V2 credentials)')}`);
    console.log(chalk.gray('\nNote: Anonymous ID is only available with legacy credentials.'));
    console.log(chalk.gray('The Public ID should match what you see in the webapp under Settings > Account.'));
  }
}