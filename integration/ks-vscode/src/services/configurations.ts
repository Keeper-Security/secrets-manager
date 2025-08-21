import type { ConfigurationChangeEvent, Event, ExtensionContext } from 'vscode';
import { EventEmitter, workspace } from 'vscode';
import { CONFIG_NAMESPACE } from '../utils/constants';
import { logger } from '../utils/logger';

export enum ConfigurationKey {
  DebugEnabled = 'debug.enabled',
  SecretDetectionEnabled = 'editor.secretDetection',
}

interface ConfigurationItems {
  [ConfigurationKey.DebugEnabled]: boolean;
  [ConfigurationKey.SecretDetectionEnabled]: boolean;
}

class Configuration {
  public configure(context: ExtensionContext): void {
    logger.logDebug('Configuring extension settings');
    context.subscriptions.push(
      workspace.onDidChangeConfiguration(
        this.onConfigurationChanged.bind(this),
        configuration
      )
    );
    logger.logDebug('Configuration change listener registered');
  }

  private _onDidChange = new EventEmitter<ConfigurationChangeEvent>();
  public get onDidChange(): Event<ConfigurationChangeEvent> {
    return this._onDidChange.event;
  }

  private onConfigurationChanged(event: ConfigurationChangeEvent): void {
    if (event.affectsConfiguration(CONFIG_NAMESPACE)) {
      logger.logDebug(
        'Configuration change detected in Keeper Security namespace'
      );
      this._onDidChange.fire(event);
    }
  }

  public get<T extends ConfigurationItems[keyof ConfigurationItems]>(
    section: ConfigurationKey
  ): T | undefined {
    const value = workspace.getConfiguration(CONFIG_NAMESPACE).get<T>(section);
    logger.logDebug(`Getting configuration value for ${section}: ${value}`);
    return value;
  }

  public set(
    section: ConfigurationKey | string,
    value: unknown
  ): Thenable<void> {
    logger.logDebug(`Setting configuration value for ${section}: ${value}`);
    return workspace.getConfiguration(CONFIG_NAMESPACE).update(section, value);
  }
}

export const configuration = new Configuration();
