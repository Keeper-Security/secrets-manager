import { SecretDetectionService } from "../../../src/services/secretDetection";


describe('Secret Detection Index', () => {
  it('should export SecretDetectionService', () => {
    expect(SecretDetectionService).toBeDefined();
    expect(typeof SecretDetectionService).toBe('function');
  });
});