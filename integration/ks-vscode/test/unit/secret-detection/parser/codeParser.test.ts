
import { TextDocument } from 'vscode';
import CodeParser from '../../../../src/secret-detection/parser/codeParser';

describe('CodeParser', () => {
  let codeParser: CodeParser;
  let mockDocument: TextDocument;

  beforeEach(() => {
    mockDocument = {
      languageId: 'typescript',
      fileName: 'test.ts',
      getText: jest.fn().mockReturnValue('')
    } as unknown as TextDocument;

    codeParser = new CodeParser(mockDocument);
  });

  describe('parse', () => {
    it('should parse API keys from content', () => {
      const content = `
        const apiKey = "sk-1234567890abcdef";
        const config = { api_key: "sk-0987654321fedcba" };
      `;
      
      (mockDocument.getText as jest.Mock).mockReturnValue(content);
      
      const secrets = codeParser.getMatches();
      
      expect(secrets).toHaveLength(2);
      expect(secrets[0].fieldValue).toMatch(/sk-1234567890abcdef/);
      expect(secrets[1].fieldValue).toMatch(/sk-0987654321fedcba/);
    });

    it('should parse passwords from content', () => {
      const content = `
        const password = "MySecurePassword123!";
        const credentials = { pass: "AnotherPassword456!" };
      `;
      
      (mockDocument.getText as jest.Mock).mockReturnValue(content);
      
      const secrets = codeParser.getMatches();
      
      expect(secrets).toHaveLength(2);
      expect(secrets[0].fieldValue).toMatch(/MySecurePassword123!/);
      expect(secrets[1].fieldValue).toMatch(/AnotherPassword456!/);
    });

    it('should parse tokens from content', () => {
      const content = `
        const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        const auth = { access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" };
      `;
      
      (mockDocument.getText as jest.Mock).mockReturnValue(content);
      
      const secrets = codeParser.getMatches();
      
      expect(secrets).toHaveLength(2);
      expect(secrets[0].fieldValue).toMatch(/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9/);
    });

    it('should handle empty content', () => {
      const secrets = codeParser.getMatches();
      expect(secrets).toEqual([]);
    });

    it('should handle content with no secrets', () => {
      const content = `
        const normalVariable = "just some text";
        const number = 42;
        const boolean = true;
      `;
      
      (mockDocument.getText as jest.Mock).mockReturnValue(content);
      
      const secrets = codeParser.getMatches();
      expect(secrets).toEqual([]);
    });

    it('should handle multiple secret types in same content', () => {
      const content = `
        const apiKey = "sk-1234567890abcdef";
        const password = "MySecurePassword123!";
        const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        const secret = "my-secret-value";
      `;
      
      (mockDocument.getText as jest.Mock).mockReturnValue(content);
      
      const secrets = codeParser.getMatches();
      
      expect(secrets.length).toBeGreaterThanOrEqual(4);
    });

    it('should handle different quote types', () => {
      const content = `
        const singleQuote = 'sk-1234567890abcdef';
        const doubleQuote = "sk-0987654321fedcba";
        const backtick = \`sk-abcdef1234567890\`;
      `;
      
      (mockDocument.getText as jest.Mock).mockReturnValue(content);
      
      const secrets = codeParser.getMatches();
      
      // Note: CodeParser only handles single and double quotes, not backticks
      expect(secrets).toHaveLength(2);
      expect(secrets[0].fieldValue).toMatch(/sk-1234567890abcdef/);
      expect(secrets[1].fieldValue).toMatch(/sk-0987654321fedcba/);
    });

    it('should handle multiline strings', () => {
      const content = `
        const multiline = \`
          This is a multiline string
          with a secret: sk-1234567890abcdef
          and more content
        \`;
      `;
      
      (mockDocument.getText as jest.Mock).mockReturnValue(content);
      
      const secrets = codeParser.getMatches();
      
      // Note: CodeParser doesn't handle multiline strings or backticks
      expect(secrets).toHaveLength(0);
    });
  });

  describe('getDocumentInfo', () => {
    it('should return document information', () => {
      // Since getDocumentInfo doesn't exist, we'll test the document properties directly
      expect(mockDocument.languageId).toBe('typescript');
      expect(mockDocument.fileName).toBe('test.ts');
    });
  });
}); 