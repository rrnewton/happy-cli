/**
 * Doctor command implementation
 *
 * Provides comprehensive diagnostics and troubleshooting information
 * for happy CLI including configuration, daemon status, logs, and links.
 *
 * IMPORTANT: The doctor must track critical issues and NOT give false
 * reassurance when there are real problems. Fail early, fail loudly.
 */

import chalk from 'chalk'
import axios from 'axios'
import { configuration } from '@/configuration'
import { readSettings, readCredentials } from '@/persistence'
import { checkIfDaemonRunningAndCleanupStaleState } from '@/daemon/controlClient'
import { findRunawayHappyProcesses, findAllHappyProcesses } from '@/daemon/doctor'
import { readDaemonState } from '@/persistence'
import { existsSync, readdirSync, statSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { projectPath } from '@/projectPath'
import packageJson from '../../package.json'

/**
 * Track critical issues found during diagnosis
 */
interface DiagnosticIssues {
  critical: string[];  // Issues that prevent happy from working
  warnings: string[];  // Issues that may cause problems
}

/**
 * Validate that credentials are valid with the server
 */
async function validateCredentialsWithServer(token: string): Promise<{ valid: boolean; error?: string }> {
  try {
    await axios.get(`${configuration.serverUrl}/v1/account/profile`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    return { valid: true };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status;
      if (status === 401 || status === 403 || status === 404 || status === 500) {
        return { valid: false, error: 'Account not found or credentials invalid' };
      }
      if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
        return { valid: false, error: `Cannot reach server: ${error.code}` };
      }
    }
    return { valid: false, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}

/**
 * Get relevant environment information for debugging
 */
export function getEnvironmentInfo(): Record<string, any> {
    return {
        PWD: process.env.PWD,
        HAPPY_HOME_DIR: process.env.HAPPY_HOME_DIR,
        HAPPY_SERVER_URL: process.env.HAPPY_SERVER_URL,
        HAPPY_PROJECT_ROOT: process.env.HAPPY_PROJECT_ROOT,
        DANGEROUSLY_LOG_TO_SERVER_FOR_AI_AUTO_DEBUGGING: process.env.DANGEROUSLY_LOG_TO_SERVER_FOR_AI_AUTO_DEBUGGING,
        NODE_ENV: process.env.NODE_ENV,
        DEBUG: process.env.DEBUG,
        workingDirectory: process.cwd(),
        processArgv: process.argv,
        happyDir: configuration?.happyHomeDir,
        serverUrl: configuration?.serverUrl,
        logsDir: configuration?.logsDir,
        processPid: process.pid,
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        user: process.env.USER,
        home: process.env.HOME,
        shell: process.env.SHELL,
        terminal: process.env.TERM,
    };
}

function getLogFiles(logDir: string): { file: string, path: string, modified: Date }[] {
    if (!existsSync(logDir)) {
        return [];
    }

    try {
        return readdirSync(logDir)
            .filter(file => file.endsWith('.log'))
            .map(file => {
                const path = join(logDir, file);
                const stats = statSync(path);
                return { file, path, modified: stats.mtime };
            })
            .sort((a, b) => b.modified.getTime() - a.modified.getTime());
    } catch {
        return [];
    }
}

/**
 * Run doctor command specifically for daemon diagnostics
 */
export async function runDoctorDaemon(): Promise<void> {
    return runDoctorCommand('daemon');
}

export async function runDoctorCommand(filter?: 'all' | 'daemon'): Promise<void> {
    // Default to 'all' if no filter specified
    if (!filter) {
        filter = 'all';
    }

    // Track issues found during diagnosis
    const issues: DiagnosticIssues = {
        critical: [],
        warnings: []
    };

    console.log(chalk.bold.cyan('\n🩺 Happy CLI Doctor\n'));

    // For 'all' filter, show everything. For 'daemon', only show daemon-related info
    if (filter === 'all') {
        // Version and basic info
        console.log(chalk.bold('📋 Basic Information'));
        console.log(`Happy CLI Version: ${chalk.green(packageJson.version)}`);
        console.log(`Platform: ${chalk.green(process.platform)} ${process.arch}`);
        console.log(`Node.js Version: ${chalk.green(process.version)}`);
        console.log('');

        // Daemon spawn diagnostics
        console.log(chalk.bold('🔧 Daemon Spawn Diagnostics'));
        const projectRoot = projectPath();
        const wrapperPath = join(projectRoot, 'bin', 'happy.mjs');
        const cliEntrypoint = join(projectRoot, 'dist', 'index.mjs');

        console.log(`Project Root: ${chalk.blue(projectRoot)}`);
        console.log(`Wrapper Script: ${chalk.blue(wrapperPath)}`);
        console.log(`CLI Entrypoint: ${chalk.blue(cliEntrypoint)}`);
        console.log(`Wrapper Exists: ${existsSync(wrapperPath) ? chalk.green('✓ Yes') : chalk.red('❌ No')}`);
        console.log(`CLI Exists: ${existsSync(cliEntrypoint) ? chalk.green('✓ Yes') : chalk.red('❌ No')}`);
        console.log('');

        // Configuration
        console.log(chalk.bold('⚙️  Configuration'));
        console.log(`Happy Home: ${chalk.blue(configuration.happyHomeDir)}`);
        console.log(`Server URL: ${chalk.blue(configuration.serverUrl)}`);
        console.log(`Logs Dir: ${chalk.blue(configuration.logsDir)}`);

        // Environment
        console.log(chalk.bold('\n🌍 Environment Variables'));
        const env = getEnvironmentInfo();
        console.log(`HAPPY_HOME_DIR: ${env.HAPPY_HOME_DIR ? chalk.green(env.HAPPY_HOME_DIR) : chalk.gray('not set')}`);
        console.log(`HAPPY_SERVER_URL: ${env.HAPPY_SERVER_URL ? chalk.green(env.HAPPY_SERVER_URL) : chalk.gray('not set')}`);
        console.log(`DANGEROUSLY_LOG_TO_SERVER: ${env.DANGEROUSLY_LOG_TO_SERVER_FOR_AI_AUTO_DEBUGGING ? chalk.yellow('ENABLED') : chalk.gray('not set')}`);
        console.log(`DEBUG: ${env.DEBUG ? chalk.green(env.DEBUG) : chalk.gray('not set')}`);
        console.log(`NODE_ENV: ${env.NODE_ENV ? chalk.green(env.NODE_ENV) : chalk.gray('not set')}`);

        // Settings
        try {
            const settings = await readSettings();
            console.log(chalk.bold('\n📄 Settings (settings.json):'));
            console.log(chalk.gray(JSON.stringify(settings, null, 2)));
        } catch (error) {
            console.log(chalk.bold('\n📄 Settings:'));
            console.log(chalk.red('❌ Failed to read settings'));
            issues.warnings.push('Failed to read settings.json');
        }

        // Authentication status - WITH SERVER VALIDATION
        console.log(chalk.bold('\n🔐 Authentication'));
        try {
            const credentials = await readCredentials();
            if (credentials) {
                console.log(chalk.gray('  Validating credentials with server...'));
                const validation = await validateCredentialsWithServer(credentials.token);
                if (validation.valid) {
                    console.log(chalk.green('✓ Authenticated (verified with server)'));
                } else {
                    console.log(chalk.red.bold('❌ CREDENTIALS INVALID'));
                    console.log(chalk.red(`   ${validation.error}`));
                    console.log(chalk.yellow('   Your local credentials do not match any account on the server.'));
                    console.log(chalk.cyan('   Fix: Run "happy auth logout" then "happy auth login"'));
                    issues.critical.push(`Credentials invalid: ${validation.error}`);
                }
            } else {
                console.log(chalk.yellow('⚠️  Not authenticated (no credentials)'));
                issues.warnings.push('Not authenticated');
            }
        } catch (error) {
            console.log(chalk.red('❌ Error reading credentials'));
            issues.warnings.push('Error reading credentials');
        }
    }

    // Daemon status - shown for both 'all' and 'daemon' filters
    console.log(chalk.bold('\n🤖 Daemon Status'));
    try {
        const isRunning = await checkIfDaemonRunningAndCleanupStaleState();
        const state = await readDaemonState();

        if (isRunning && state) {
            console.log(chalk.green('✓ Daemon is running'));
            console.log(`  PID: ${state.pid}`);
            console.log(`  Started: ${new Date(state.startTime).toLocaleString()}`);
            console.log(`  CLI Version: ${state.startedWithCliVersion}`);
            if (state.httpPort) {
                console.log(`  HTTP Port: ${state.httpPort}`);
            }
        } else if (state && !isRunning) {
            console.log(chalk.yellow('⚠️  Daemon state exists but process not running (stale)'));
        } else {
            console.log(chalk.red('❌ Daemon is not running'));
        }

        // Show daemon state file
        if (state) {
            console.log(chalk.bold('\n📄 Daemon State:'));
            console.log(chalk.blue(`Location: ${configuration.daemonStateFile}`));
            console.log(chalk.gray(JSON.stringify(state, null, 2)));
        }

        // All Happy processes
        const allProcesses = await findAllHappyProcesses();
        if (allProcesses.length > 0) {
            console.log(chalk.bold('\n🔍 All Happy CLI Processes'));

            // Group by type
            const grouped = allProcesses.reduce((groups, process) => {
                if (!groups[process.type]) groups[process.type] = [];
                groups[process.type].push(process);
                return groups;
            }, {} as Record<string, typeof allProcesses>);

            // Display each group
            Object.entries(grouped).forEach(([type, processes]) => {
                const typeLabels: Record<string, string> = {
                    'current': '📍 Current Process',
                    'daemon': '🤖 Daemon',
                    'daemon-version-check': '🔍 Daemon Version Check (stuck)',
                    'daemon-spawned-session': '🔗 Daemon-Spawned Sessions',
                    'user-session': '👤 User Sessions',
                    'dev-daemon': '🛠️  Dev Daemon',
                    'dev-daemon-version-check': '🛠️  Dev Daemon Version Check (stuck)',
                    'dev-session': '🛠️  Dev Sessions',
                    'dev-doctor': '🛠️  Dev Doctor',
                    'dev-related': '🛠️  Dev Related',
                    'doctor': '🩺 Doctor',
                    'unknown': '❓ Unknown'
                };

                console.log(chalk.blue(`\n${typeLabels[type] || type}:`));
                processes.forEach(({ pid, command }) => {
                    const color = type === 'current' ? chalk.green :
                        type.startsWith('dev') ? chalk.cyan :
                            type.includes('daemon') ? chalk.blue : chalk.gray;
                    console.log(`  ${color(`PID ${pid}`)}: ${chalk.gray(command)}`);
                });
            });
        } else {
            console.log(chalk.red('❌ No happy processes found'));
        }

        if (filter === 'all' && allProcesses.length > 1) { // More than just current process
            console.log(chalk.bold('\n💡 Process Management'));
            console.log(chalk.gray('To clean up runaway processes: happy doctor clean'));
        }
    } catch (error) {
        console.log(chalk.red('❌ Error checking daemon status'));
    }

    // Log files - only show for 'all' filter
    if (filter === 'all') {
        console.log(chalk.bold('\n📝 Log Files'));

        // Get ALL log files
        const allLogs = getLogFiles(configuration.logsDir);
        
        if (allLogs.length > 0) {
            // Separate daemon and regular logs
            const daemonLogs = allLogs.filter(({ file }) => file.includes('daemon'));
            const regularLogs = allLogs.filter(({ file }) => !file.includes('daemon'));

            // Show regular logs (max 10)
            if (regularLogs.length > 0) {
                console.log(chalk.blue('\nRecent Logs:'));
                const logsToShow = regularLogs.slice(0, 10);
                logsToShow.forEach(({ file, path, modified }) => {
                    console.log(`  ${chalk.green(file)} - ${modified.toLocaleString()}`);
                    console.log(chalk.gray(`    ${path}`));
                });
                if (regularLogs.length > 10) {
                    console.log(chalk.gray(`  ... and ${regularLogs.length - 10} more log files`));
                }
            }

            // Show daemon logs (max 5)
            if (daemonLogs.length > 0) {
                console.log(chalk.blue('\nDaemon Logs:'));
                const daemonLogsToShow = daemonLogs.slice(0, 5);
                daemonLogsToShow.forEach(({ file, path, modified }) => {
                    console.log(`  ${chalk.green(file)} - ${modified.toLocaleString()}`);
                    console.log(chalk.gray(`    ${path}`));
                });
                if (daemonLogs.length > 5) {
                    console.log(chalk.gray(`  ... and ${daemonLogs.length - 5} more daemon log files`));
                }
            } else {
                console.log(chalk.yellow('\nNo daemon log files found'));
            }
        } else {
            console.log(chalk.yellow('No log files found'));
        }

        // Support and bug reports
        console.log(chalk.bold('\n🐛 Support & Bug Reports'));
        console.log(`Report issues: ${chalk.blue('https://github.com/slopus/happy-cli/issues')}`);
        console.log(`Documentation: ${chalk.blue('https://happy.engineering/')}`);
    }

    // Final diagnosis summary - DO NOT give false reassurance!
    console.log('');
    if (issues.critical.length > 0) {
        console.log(chalk.red.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
        console.log(chalk.red.bold('❌ CRITICAL ISSUES FOUND'));
        console.log(chalk.red.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
        issues.critical.forEach(issue => {
            console.log(chalk.red(`  • ${issue}`));
        });
        console.log('');
        console.log(chalk.yellow('These issues must be fixed before happy will work correctly.'));
        console.log('');
    } else if (issues.warnings.length > 0) {
        console.log(chalk.yellow.bold('⚠️  Diagnosis complete with warnings:'));
        issues.warnings.forEach(issue => {
            console.log(chalk.yellow(`  • ${issue}`));
        });
        console.log('');
    } else {
        console.log(chalk.green('✅ Doctor diagnosis complete - no issues found!\n'));
    }
}