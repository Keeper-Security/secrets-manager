import { CommandService } from "../../../src/commands";
import { BaseCommandHandler } from "../../../src/commands/handlers/baseCommandHandler";


describe('Commands Index', () => {
  it('should export CommandService', () => {
    expect(CommandService).toBeDefined();
    expect(typeof CommandService).toBe('function');
  });
  it('should export BaseCommandHandler', () => {
    expect(BaseCommandHandler).toBeDefined();
    expect(typeof BaseCommandHandler).toBe('function');
  });
}); 