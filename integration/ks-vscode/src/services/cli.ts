import { env, ExtensionContext, Uri, window } from 'vscode';
import { logger } from '../utils/logger';
import { promisifyExec, StatusBarSpinner } from '../utils/helper';
import { exec, spawn, ChildProcess } from 'child_process';
import { EventEmitter } from 'events';
import { KEEPER_COMMANDER_DOCS_URLS } from '../utils/constants';
import { HELPER_MESSAGES } from '../utils/constants';

// Patterns to filter out from Keeper Commander output (not real errors)
const BENIGN_PATTERNS = [
  /Logging in to Keeper Commander/i,
  /Attempting biometric authentication/i,
  /Successfully authenticated with Biometric Login/i,
  /Press Ctrl\+C to skip biometric/i,
  /and use default login method/i,
  /Syncing\.\.\./i,
  /Decrypted\s*\[\d+\]\s*record\(s\)/i,
  /^keeper shell$/i,
  /^\r$/, // stray carriage returns
];

// Remove benign noise from command output to focus on real errors
function cleanCommanderNoise(text: string): string {
  if (!text) {
    return '';
  }
  
  let out = text;
  for (const rx of BENIGN_PATTERNS) {
    out = out.replace(new RegExp(rx.source + '.*?(\\n|$)', 'gim'), '');
  }
  
  return out.trim();
}

// Check if output contains actual error messages (not just noise)
function isRealError(text: string): boolean {
  const t = text.trim();
  if (!t) {
    return false;
  }
  // if only benign lines remain, treat as non-error
  const cleaned = cleanCommanderNoise(t);
  if (!cleaned) {
    return false;
  }
  // conservative error keywords
  return /(error|failed|exception|traceback)/i.test(cleaned);
}

// Extract command output between echoed command and shell prompt
function extractCommandOutput(
  fullOutput: string, 
  command: string, 
  args: string[]
): string {
  const commandString = `${command} ${args.join(' ')}`.trim();
  
  const commandVariations = [
    // Exact command after shell prompt
    `My Vault> ${commandString}`,
    // Command with flexible whitespace after prompt
    `My Vault>\\s*${commandString}`,
    // Command at end of line
    `${commandString}\\s*$`,
    // Command with flexible whitespace
    `${commandString.replace(/\\s+/g, '\\s+')}`,
    // Just the command name
    command,
  ];
  
  let commandStart = -1;
  let foundCommand = '';
  
  // Try each variation
  for (const variation of commandVariations) {
    let found = -1;
    
    if (variation.includes('\\s+') || variation.includes('\\s*')) {
      // Use regex for flexible patterns
      const regex = new RegExp(variation, 'i');
      const match = fullOutput.match(regex);
      if (match) {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        found = match.index!;
        foundCommand = match[0];
        commandStart = found;
        break;
      }
    } else {
      // Use simple string search
      found = fullOutput.indexOf(variation);
      if (found !== -1) {
        foundCommand = variation;
        commandStart = found;
        break;
      }
    }
  }
  
  if (commandStart !== -1) {
    // Command found, extract output
    const lastPromptIndex = fullOutput.lastIndexOf('My Vault>');
    if (lastPromptIndex !== -1) {
      const outputStart = commandStart + foundCommand.length;
      const outputEnd = lastPromptIndex;
      
      if (outputStart < outputEnd) {
        const extractedOutput = fullOutput.substring(outputStart, outputEnd);
        return extractedOutput.trim();
      }
    }
  }
  
  // FALLBACK: Try to find the last command pattern
  const lastPromptIndex = fullOutput.lastIndexOf('My Vault>');
  if (lastPromptIndex !== -1) {
    // Look for the last "My Vault> command" pattern
    const lastCommandPattern = /My Vault>\s*([^\n]*)$/m;
    const match = fullOutput.substring(0, lastPromptIndex).match(lastCommandPattern);
    
    if (match) {      
      // Remove the last command line
      const withoutLastCommand = fullOutput.substring(0, lastPromptIndex).replace(lastCommandPattern, '');
      return withoutLastCommand.trim();
    }
    
    // If no command pattern found, just remove everything after last shell prompt
    return fullOutput.substring(0, lastPromptIndex).trim();
  }
  
  return fullOutput;
}

// Create a special error type that won't trigger persistent mode fallback
class CommandBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CommandBlockedError';
  }
}

export class CliService {
  private isInstalled: boolean = false;
  private isAuthenticated: boolean = false;
  private persistentProcess: ChildProcess | null = null;
  private processEmitter = new EventEmitter();
  private isInitialized = false;
  private usePersistentProcess = false;
  private shellReady = false;
  private shellReadyPromise: Promise<void> | null = null;
  private isExecutingCommand = false;

  public constructor(
    // @ts-ignore
    private context: ExtensionContext,
    private spinner: StatusBarSpinner
  ) { }

  // Lazy initialization method - only runs when first needed
  private async lazyInitialize(): Promise<void> {
    if (this.isInitialized) {
      logger.logDebug(
        'CliService.lazyInitialize: Already initialized, skipping'
      );
      return;
    }

    try {
      logger.logDebug('CliService.lazyInitialize: Starting initialization');
      this.spinner.show('Initializing Keeper Security Extension...');

      logger.logDebug(
        'CliService.lazyInitialize: Checking commander installation and authentication'
      );
      // Check both installation and authentication concurrently for efficiency
      const [isInstalled, isAuthenticated] = await Promise.all([
        this.checkCommanderInstallation(),
        this.checkCommanderAuth(),
      ]);

      this.isInstalled = isInstalled;
      this.isAuthenticated = isAuthenticated;
      logger.logDebug(
        `CliService.lazyInitialize: Installation check: ${isInstalled}, Authentication check: ${isAuthenticated}`
      );

      if (!isInstalled) {
        logger.logError('Keeper Commander CLI is not installed');
        this.spinner.hide();
        await this.promptCommanderInstallationError();
        return;
      }

      if (!isAuthenticated) {
        logger.logError('Keeper Commander CLI is not authenticated');
        this.spinner.hide();
        await this.promptManualAuthenticationError();
        return;
      }

      logger.logDebug(
        'CliService.lazyInitialize: Switching to persistent process mode'
      );

      // After successful auth check, switch to persistent process mode for better performance
      this.usePersistentProcess = true;
      this.isInitialized = true;

      logger.logInfo('Keeper Security Extension initialized successfully');
    } catch (error) {
      logger.logError(
        'Failed to initialize Keeper Security Extension status',
        error
      );
      this.isInstalled = false;
      this.isAuthenticated = false;
    } finally {
      this.spinner.hide();
    }
  }

  // Check if Keeper Commander CLI is installed by running --version
  private async checkCommanderInstallation(): Promise<boolean> {
    try {
      // Use the legacy method for initial checks (before persistent process is ready)
      const stdout = await this.executeCommanderCommandLegacy('--version');

      // Look for version string in output
      const isInstalled = stdout.includes('version');
      logger.logInfo(`Keeper Commander CLI Installed: YES`);

      return isInstalled;
    } catch (error: unknown) {
      logger.logError(
        'Keeper Commander CLI Installation check failed:',
        error instanceof Error ? error.message : 'Unknown error'
      );
      return false;
    }
  }

  // Check if user is authenticated with Keeper Commander
  private async checkCommanderAuth(): Promise<boolean> {
    /**
     * TODO: IN FUTURE WE WILL NOT USE this-device command, WILL USE 'whoami' command instead
     */
    try {
      // Create timeout promise to prevent hanging on interactive login prompts
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(
          () => reject(new Error('Must be asking for interactive login')),
          30000 // 30 second timeout for auth check
        );
      });

      // Create execution promise for the actual auth check
      const execPromise = this.executeCommanderCommandLegacyRaw('this-device');

      // Race between execution and timeout to prevent hanging
      const { stdout, stderr } = await Promise.race([
        execPromise,
        timeoutPromise,
      ]);

      const out = `${stdout}\n${stderr}`;
      const persistentOn = /Persistent Login:\s*ON/i.test(out);

      // Look for biometric authentication hints in output
      const biometricHints = [
        /Press Ctrl\+C to skip biometric/i,
        /Attempting biometric authentication/i,
        /Successfully authenticated with Biometric Login/i,
        /Syncing\.\.\./i,
        /Decrypted\s*\[\d+\]\s*record\(s\)/i,
      ];
      const biometricDetected = biometricHints.some((rx) => rx.test(out));

      if (persistentOn || biometricDetected) {
        const mode = persistentOn ? 'Persistent' : 'Biometric';
        logger.logInfo(`Keeper Commander CLI Authenticated: YES (${mode})`);
        return true;
      }

      logger.logInfo('Keeper Commander CLI Authenticated: NO');
      return false;
    } catch (error: unknown) {
      logger.logError(
        'Keeper Commander CLI Authentication check failed:',
        error instanceof Error ? error.message : 'Unknown error'
      );
      return false;
    }
  }

  // add a raw executor (no cleaning)
  private async executeCommanderCommandLegacyRaw(
    command: string,
    args: string[] = []
  ): Promise<{ stdout: string; stderr: string }> {
    const fullCommand = `keeper ${command} ${args.join(' ')}`;
    const { stdout, stderr } = await promisifyExec(exec)(fullCommand);
    return { stdout: String(stdout || ''), stderr: String(stderr || '') };
  }

  // keep the cleaned version for normal use
  public async executeCommanderCommandLegacy(
    command: string,
    args: string[] = []
  ): Promise<string> {
    try {
      const { stdout, stderr } = await this.executeCommanderCommandLegacyRaw(
        command,
        args
      );
      const cleanStdout = cleanCommanderNoise(stdout);
      const cleanStderr = cleanCommanderNoise(stderr);
      if (isRealError(cleanStderr)) {
        throw new Error(cleanStderr);
      }
      return cleanStdout || stdout;
    } catch (error) {
      logger.logError(`Legacy commander command failed`, error);
      throw error;
    }
  }

  public async executeCommanderCommand(
    command: string,
    args: string[] = []
  ): Promise<string> {
    // Initialize on first use
    if (!this.isInitialized) {
      await this.lazyInitialize();
    }

    // If initialization failed or persistent process is disabled, use legacy method
    if (!this.usePersistentProcess) {
      logger.logInfo(`Using legacy mode for command: ${command}`);
      return this.executeCommanderCommandLegacy(command, args);
    }

    try {
      return await this.executeCommanderCommandPersistent(command, args);
    } catch (error) {
      // Don't fallback to legacy mode for blocked commands
      if (error instanceof CommandBlockedError) {
        throw error; // Re-throw without disabling persistent mode
      }
      
      logger.logError(`Persistent process failed, falling back to legacy mode:`, error);
      this.usePersistentProcess = false;
      return this.executeCommanderCommandLegacy(command, args);
    }
  }

  // Simple persistent command execution with timeout protection (NO persistent mode kill)
  private async executeCommanderCommandPersistent(
    command: string,
    args: string[]
  ): Promise<string> {
    // Ensure shell process is ready
    await this.ensurePersistentProcess();

    // Check if another command is running
    if (this.isExecutingCommand) {
      logger.logInfo(`Command ${command} blocked - another command is executing`);
            
      // Throw special error that won't trigger persistent mode fallback
      throw new CommandBlockedError(`Another Keeper command is currently running. Please wait for it to complete and try again.`);
    }

    // Set executing flag
    this.isExecutingCommand = true;

    try {
      // Execute the command directly (with 60-second execution timeout)
      const result = await this.executeCommandInProcess(command, args);
      return result;
    } finally {
      // Always clear the flag
      this.isExecutingCommand = false;
    }
  }

  // Ensure persistent process exists and is ready to accept commands
  private async ensurePersistentProcess(): Promise<void> {
    if (!this.persistentProcess || this.persistentProcess.killed) {
      // Create new process if needed
      await this.createPersistentProcess();
    }
    if (!this.shellReady && this.shellReadyPromise) {
      // Wait for shell to be ready
      await this.shellReadyPromise;
    }
  }

  // Create new persistent Keeper Commander shell process
  private async createPersistentProcess(): Promise<void> {
    try {
      logger.logInfo('Creating persistent Keeper Commander process...');

      this.shellReady = false;
      this.shellReadyPromise = null;

      // Use platform-aware spawning
      if (process.platform === 'win32') {
        // On Windows, use CMD to handle the 'keeper' alias
        this.persistentProcess = spawn('cmd', ['/c', 'keeper', 'shell'], {
          stdio: ['pipe', 'pipe', 'pipe'],
          shell: false,
        });
      } else {
        // On other platforms, spawn directly
        this.persistentProcess = spawn('keeper', ['shell'], {
          stdio: ['pipe', 'pipe', 'pipe'],
          shell: false,
        });
      }

      // Handle process creation errors
      this.persistentProcess.on('error', (error) => {
        logger.logError('Persistent process error:', error);
        this.handleProcessError();
      });

      // Handle process exit
      this.persistentProcess.on('exit', (code) => {
        logger.logInfo(`Persistent process exited with code: ${code}`);
        this.handleProcessExit();
      });

      // Startup listeners: consume noise until shell is ready
      const onStdoutStartup = (chunk: Buffer): void => {
        const data = chunk.toString();

        // Look for shell prompt
        if (data.includes('My Vault>') || data.includes('$')) {
          // Remove startup listener
          this.persistentProcess?.stdout?.off('data', onStdoutStartup);

          // After ready, attach the real forwarders for command execution
          this.persistentProcess?.stdout?.on('data', (d) => {
            // Forward stdout to command handlers
            this.processEmitter.emit('stdout', d.toString());
          });
          this.persistentProcess?.stderr?.on('data', (d) => {
            // Forward stderr to command handlers
            this.processEmitter.emit('stderr', d.toString());
          });

          // Mark shell as ready for commands
          this.shellReady = true;
        }
      };
      this.persistentProcess.stdout?.on('data', onStdoutStartup);

      // readiness promise with timeout
      this.shellReadyPromise = new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error('Shell ready timeout')),
          60000 // 60 seconds timeout
        );
        const onReady = (chunk: Buffer): void => {
          const data = chunk.toString();
          if (data.includes('My Vault>') || data.includes('$')) {
            clearTimeout(timeout);
            this.persistentProcess?.stdout?.off('data', onReady);
            resolve();
          }
        };
        this.persistentProcess?.stdout?.on('data', onReady);
      });

      await this.shellReadyPromise;
      logger.logInfo('Persistent Keeper Commander process ready');
    } catch (error) {
      logger.logError('Failed to create persistent process:', error);
      // Clean up any partial state
      this.handleProcessError();

      // Re-throw the error so caller knows it failed
      throw error;
    }
  }

  private async executeCommandInProcess(
    command: string,
    args: string[]
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        const errorMessage = `Command execution timeout: ${command} ${args.join(' ')}`;
        logger.logError(errorMessage);
        
        // Show error notification to user
        window.showErrorMessage(
          `Keeper Command Timeout:`,
          'The command took too long to execute and timed out. Please try again.'
        );

        this.spinner.hide();
        
        // Try to recover the persistent process
        this.recoverPersistentProcess();
        
        reject(new Error('Command execution timeout'));
      }, 60000);

      // Accumulate stdout for command result
      let output = '';
      let errorOutput = '';
      let biometricPromptHandled = false;

      // Handle stdout data from Keeper process
      const onStdout = (data: string): void => {
        const dataStr = data.toString();

        // Handle biometric authentication prompts automatically
        if (dataStr.includes('Press Ctrl+C to skip biometric')) {
          if (!biometricPromptHandled) {
            biometricPromptHandled = true;
            logger.logInfo('Biometric prompt detected, sending Ctrl+C to skip...');
            // Send Ctrl+C to skip biometric authentication
            this.persistentProcess?.stdin?.write('\x03');

            setTimeout(() => {
              this.persistentProcess?.stdin?.write(`${command} ${args.join(' ')}\n`);
            }, 500);
            return;
          }
        }

        // Check for authentication expiration
        if (dataStr.includes('Not logged in')) {
          cleanup();
          this.handleAuthenticationExpired();
          reject(new Error('Authentication expired. Please log in again.'));
          return;
        }

        // Add to output if not biometric prompt
        if (!dataStr.includes('Press Ctrl+C to skip biometric')) {
          output += dataStr;
        }
      };

      // Handle stderr data
      const onStderr = (data: string): void => {
        const dataStr = data.toString();
        
        if (dataStr.includes('Not logged in')) {
          cleanup();
          this.handleAuthenticationExpired();
          reject(new Error('Authentication expired. Please log in again.'));
          return;
        }

        errorOutput += dataStr;
      };

      // Clean up event listeners and timeouts
      const cleanup = (): void => {
        clearTimeout(timeout);
        this.processEmitter.removeListener('stdout', onStdout);
        this.processEmitter.removeListener('stderr', onStderr);
      };

      // Listen for stdout events
      this.processEmitter.on('stdout', onStdout);
      // Listen for stderr events
      this.processEmitter.on('stderr', onStderr);

      // Send command to Keeper Commander process via stdin
      this.persistentProcess?.stdin?.write(`${command} ${args.join(' ')}\n`);

      // Wait for command completion by checking for shell prompt
      const checkCompletion = (): void => {
        // Check for shell prompt
        if (output.includes('My Vault>') || output.includes('$')) {
          // Clean up listeners and timeouts
          cleanup();
          
          // Extract output between command echo and shell prompt
          const cleanOut = extractCommandOutput(output, command, args);
          
          // Clean benign noise from stderr only (stdout is already clean)
          const cleanErr = cleanCommanderNoise(errorOutput);
          
          // Check if stderr contains real errors
          if (isRealError(cleanErr)) {
            reject(new Error(cleanErr));
          } else {
            resolve(cleanOut);
          }
        } else {
          // Check again in 100ms if no prompt yet
          setTimeout(checkCompletion, 100);
        }
      };

      // Start checking for completion
      checkCompletion();
    });
  }

  // Simple authentication expiration handler
  private handleAuthenticationExpired(): void {
    this.isAuthenticated = false;
    this.usePersistentProcess = false;
    this.isInitialized = false;

    if (this.persistentProcess) {
      this.persistentProcess.kill();
      this.persistentProcess = null;
    }

    this.promptManualAuthenticationError();
  }

  // Enhanced error handling with detailed logging
  private handleProcessError(): void {
    logger.logError('Handling process error');
    
    // Clear the failed process
    this.persistentProcess = null;
  }

  // Enhanced process exit handling with detailed logging
  private handleProcessExit(): void {
    logger.logInfo('Handling process exit');
    
    // Clear the exited process
    this.persistentProcess = null;
  }

  // Show user-friendly error when Keeper Commander is not installed
  private async promptCommanderInstallationError(): Promise<void> {
    const action = await window.showErrorMessage(
      HELPER_MESSAGES.CLI_NOT_INSTALLED,
      HELPER_MESSAGES.OPEN_INSTALLATION_DOCS
    );

    if (action === HELPER_MESSAGES.OPEN_INSTALLATION_DOCS) {
      const docsUrl = Uri.parse(KEEPER_COMMANDER_DOCS_URLS.INSTALLATION);
      // Open installation documentation
      env.openExternal(docsUrl);
    }
  }

  // Show user-friendly error when authentication fails
  private async promptManualAuthenticationError(): Promise<void> {
    const action = await window.showErrorMessage(
      HELPER_MESSAGES.CLI_NOT_AUTHENTICATED,
      HELPER_MESSAGES.OPEN_AUTHENTICATION_DOCS
    );

    if (action === HELPER_MESSAGES.OPEN_AUTHENTICATION_DOCS) {
      const docsUrl = Uri.parse(KEEPER_COMMANDER_DOCS_URLS.AUTHENTICATION);
      // Open authentication documentation
      env.openExternal(docsUrl);
    }
  }

  // Check if CLI is ready to execute commands
  public async isCLIReady(): Promise<boolean> {
    // Lazy initialize if not done yet
    if (!this.isInitialized) {
      await this.lazyInitialize();
    }

    if (!this.isInstalled || !this.isAuthenticated) {
      return false;
    }

    return true;
  }

  // Enhanced disposal with cleanup
  public dispose(): void {
    logger.logDebug('Disposing CLI service');
    
    // Kill persistent process
    if (this.persistentProcess) {
      this.persistentProcess.kill();
      this.persistentProcess = null;
    }
    
    logger.logDebug('CLI service disposed');
  }

  private recoverPersistentProcess(): void {
    logger.logInfo('Attempting to recover persistent process after timeout');
    
    // Kill the stuck process
    if (this.persistentProcess) {
      this.persistentProcess.kill();
      this.persistentProcess = null;
    }
    
    // Reset shell state
    this.shellReady = false;
    this.shellReadyPromise = null;  
  }
}
