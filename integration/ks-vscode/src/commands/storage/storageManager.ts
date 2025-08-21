import { ExtensionContext, window, QuickPickItem } from 'vscode';
import { CliService } from '../../services/cli';
import { ICliListFolderResponse, ICurrentStorage, IFolder } from '../../types';
import { resolveFolderPaths } from '../../utils/helper';
import { logger } from '../../utils/logger';
import { StatusBarSpinner } from '../../utils/helper';
import { safeJsonParse } from '../../utils/helper';

export class StorageManager {
  constructor(
    private context: ExtensionContext,
    private cliService: CliService,
    private spinner: StatusBarSpinner
  ) {
    logger.logDebug('StorageManager initialized');
  }

  async validateCurrentStorage(): Promise<boolean> {
    logger.logDebug('Starting storage validation');
    this.spinner.show('Validating storage...');

    const currentStorage = this.getCurrentStorage();
    logger.logDebug(
      `Current storage: ${currentStorage ? currentStorage.name : 'null'}`
    );

    if (!currentStorage) {
      logger.logDebug('No current storage found');
      return false;
    }

    // check if current storage is a My Vault
    if (currentStorage.folderUid === '/') {
      logger.logDebug('Current storage is My Vault, validation successful');
      return true;
    }

    // Sync-down the latest records from the vault
    logger.logDebug('StorageManager: Syncing down latest records from vault');
    await this.cliService.executeCommanderCommand('sync-down');

    // Fetch all folders from server
    logger.logDebug('Fetching folders from server for validation');
    const allAvailableFolders = await this.cliService.executeCommanderCommand(
      'ls',
      ['--format=json', '-f', '-R']
    );

    // Use safe parser that cleans output first
    const parsedFolders: ICliListFolderResponse[] = safeJsonParse(allAvailableFolders, []);
    logger.logDebug(`Retrieved ${parsedFolders.length} folders from server`);

    // Check if stored folder still exists
    const folderExists = parsedFolders.some(
      (folder) => folder.folder_uid === currentStorage.folderUid
    );

    logger.logDebug(
      `Folder "${currentStorage.name}" exists on server: ${folderExists}`
    );

    if (!folderExists) {
      logger.logError(
        `Folder "${currentStorage.name}" no longer exists on Keeper vault`
      );
      this.setCurrentStorage(null);
      return false;
    }

    logger.logDebug('Storage validation completed successfully');
    this.spinner.hide();
    return true;
  }

  async ensureValidStorage(): Promise<void> {
    logger.logDebug('Ensuring valid storage');
    // if currentStorage is not set, choose a folder
    if (!this.getCurrentStorage()) {
      logger.logDebug(
        'No current storage found, prompting for folder selection'
      );
      await this.chooseFolder();
    } else {
      logger.logDebug('Current storage exists, validating...');
      // Validate current storage
      const isFolderExistsOnKeeperVault = await this.validateCurrentStorage();
      if (!isFolderExistsOnKeeperVault) {
        logger.logDebug(
          'Current storage validation failed, prompting for new selection'
        );
        // Show warning about invalid folder and prompt for new selection
        const shouldChooseNew = await window.showWarningMessage(
          'Previously selected folder is no longer available. Would you like to choose a new folder?',
          'Yes',
          'No'
        );
        if (shouldChooseNew === 'Yes') {
          await this.chooseFolder();
        } else {
          logger.logDebug('User chose not to select new folder');
          return;
        }
      } else {
        logger.logDebug('Current storage validation successful');
      }
    }
  }

  async chooseFolder(): Promise<void> {
    logger.logDebug('Starting folder selection process');

    // get all folders from vault
    this.spinner.show('Retrieving folders...');

    // Sync-down the latest records from the vault
    logger.logDebug('StorageManager: Syncing down latest records from vault');
    await this.cliService.executeCommanderCommand('sync-down');

    logger.logDebug('Fetching folders from Keeper vault');

    const allAvailableFolders = await this.cliService.executeCommanderCommand(
      'ls',
      ['--format=json', '-f', '-R']
    );
    this.spinner.hide();

    const rootVault: ICurrentStorage = {
      folderUid: '/',
      name: 'My Vault',
      parentUid: '/',
      folderPath: '/',
    };

    // Use safe parser that cleans output first
    const parsedFolders = safeJsonParse(allAvailableFolders, []);
    logger.logDebug(`Retrieved ${parsedFolders.length} folders from vault`);

    // If no folders available, automatically set root vault and skip quick pick
    if (parsedFolders.length === 0) {
      logger.logDebug('No folders available, automatically setting root vault as storage');
      this.setCurrentStorage(rootVault);

      window.showInformationMessage(
        `Storage location set to "${rootVault.name}" folder (no other folders available)`
      );
      logger.logDebug(`Storage location automatically set to: ${rootVault.name}`);
      return;
    }


    const allAvailableFoldersWithPaths = [
      rootVault,
      ...resolveFolderPaths(parsedFolders),
    ];

    // Only show quick pick if there are multiple folder options
    const formatedFoldersForQuickPick = allAvailableFoldersWithPaths.map(
      (folder: ICurrentStorage) => {
        const response: QuickPickItem & { value: string } = {
          label: folder.name,
          value: folder.folderUid,
          picked: this.getCurrentStorage()?.folderUid === folder.folderUid,
        };
        if (folder.folderPath && folder.folderPath !== '/') {
          response.detail = `Path: ${folder.folderPath}`;
        }
        return response;
      }
    );

    // show picker for folders
    logger.logDebug('Showing folder selection picker');
    const selectedFolder = await window.showQuickPick(
      formatedFoldersForQuickPick,
      {
        title: 'Available folders from Keeper Vault',
        placeHolder:
          'Select a folder to use as storage location while saving secrets',
        matchOnDetail: true,
        ignoreFocusOut: true,
      }
    );

    if (!selectedFolder) {
      logger.logDebug('No folder selected by user');
      return;
    }

    logger.logDebug(
      `User selected folder: ${selectedFolder.label} (${selectedFolder.value})`
    );

    // if folder is selected, set currentStorage to the folder
    const newStorage =
      allAvailableFoldersWithPaths.find(
        (folder: IFolder) => folder.folderUid === selectedFolder.value
      ) || null;

    this.setCurrentStorage(newStorage);

    window.showInformationMessage(
      `Storage location set to "${selectedFolder.label}" folder`
    );
    logger.logDebug(`Storage location updated to: ${selectedFolder.label}`);
  }

  getCurrentStorage(): ICurrentStorage | null {
    const storage = this.context.workspaceState.get('currentStorage', null);
    logger.logDebug(
      `Retrieved current storage: ${storage ? JSON.stringify(storage) : 'null'}`
    );
    return storage;
  }

  setCurrentStorage(storage: ICurrentStorage | null): void {
    logger.logDebug(
      `Setting current storage to: ${storage ? JSON.stringify(storage) : 'null'}`
    );
    this.context.workspaceState.update('currentStorage', storage);
  }
}
