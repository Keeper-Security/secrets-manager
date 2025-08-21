import { configuration, ConfigurationKey, Core } from "../../../src/services";
import { CliService } from "../../../src/services/cli";


describe('Services Index', () => {
  it('should export CliService', () => {
    expect(CliService).toBeDefined();
    expect(typeof CliService).toBe('function');
  });

  it('should export configuration', () => {
    expect(configuration).toBeDefined();
    expect(configuration.configure).toBeDefined();
    expect(configuration.get).toBeDefined();
    expect(configuration.set).toBeDefined();
  });

  it('should export ConfigurationKey enum', () => {
    expect(ConfigurationKey).toBeDefined();
    expect(ConfigurationKey.DebugEnabled).toBe('debug.enabled');
    expect(ConfigurationKey.SecretDetectionEnabled).toBe('editor.secretDetection');
  });

  it('should export Core class', () => {
    expect(Core).toBeDefined();
    expect(typeof Core).toBe('function');
  });
});