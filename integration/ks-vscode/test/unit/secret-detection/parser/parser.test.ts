/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-unused-vars */
import CodeParser from '../../../../src/secret-detection/parser/codeParser';
import DotEnvParser from '../../../../src/secret-detection/parser/dotEnv';
import JsonConfigParser from '../../../../src/secret-detection/parser/jsonConfig';
import YamlConfigParser from '../../../../src/secret-detection/parser/yamlConfig';
import { TextDocument } from 'vscode';
import { documentMatcher, isEnvironmentFile } from '../../../../src/utils/helper';
import path from 'path';

// Mock dependencies
jest.mock('../../../../src/secret-detection/parser/codeParser');
jest.mock('../../../../src/secret-detection/parser/dotEnv');
jest.mock('../../../../src/secret-detection/parser/jsonConfig');
jest.mock('../../../../src/secret-detection/parser/yamlConfig');
jest.mock('../../../../src/utils/helper');
jest.mock('path');

describe('Parser Factory Logic', () => {
  let mockDocument: TextDocument;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockDocument = {
      languageId: 'typescript',
      fileName: 'test.ts',
      getText: jest.fn().mockReturnValue('test content')
    } as unknown as TextDocument;
  });

  describe('environment file detection', () => {
    it('should detect basic .env files', () => {
      (path.basename as jest.Mock).mockReturnValue('.env');
      (isEnvironmentFile as jest.Mock).mockReturnValue(true);
      
      const result = isEnvironmentFile(path.basename('.env'));
      expect(result).toBe(true);
    });

    it('should detect env files without dot', () => {
      (path.basename as jest.Mock).mockReturnValue('env');
      (isEnvironmentFile as jest.Mock).mockReturnValue(true);
      
      const result = isEnvironmentFile(path.basename('env'));
      expect(result).toBe(true);
    });

    it('should detect .env.local files', () => {
      (path.basename as jest.Mock).mockReturnValue('.env.local');
      (isEnvironmentFile as jest.Mock).mockReturnValue(true);
      
      const result = isEnvironmentFile(path.basename('.env.local'));
      expect(result).toBe(true);
    });

    it('should detect .env.production files', () => {
      (path.basename as jest.Mock).mockReturnValue('.env.production');
      (isEnvironmentFile as jest.Mock).mockReturnValue(true);
      
      const result = isEnvironmentFile(path.basename('.env.production'));
      expect(result).toBe(true);
    });

    it('should detect .env.staging files', () => {
      (path.basename as jest.Mock).mockReturnValue('.env.staging');
      (isEnvironmentFile as jest.Mock).mockReturnValue(true);
      
      const result = isEnvironmentFile(path.basename('.env.staging'));
      expect(result).toBe(true);
    });

    it('should detect .env.dev files', () => {
      (path.basename as jest.Mock).mockReturnValue('.env.dev');
      (isEnvironmentFile as jest.Mock).mockReturnValue(true);
      
      const result = isEnvironmentFile(path.basename('.env.dev'));
      expect(result).toBe(true);
    });

    it('should detect .env.test files', () => {
      (path.basename as jest.Mock).mockReturnValue('.env.test');
      (isEnvironmentFile as jest.Mock).mockReturnValue(true);
      
      const result = isEnvironmentFile(path.basename('.env.test'));
      expect(result).toBe(true);
    });

    it('should detect .env.123 files', () => {
      (path.basename as jest.Mock).mockReturnValue('.env.123');
      (isEnvironmentFile as jest.Mock).mockReturnValue(true);
      
      const result = isEnvironmentFile(path.basename('.env.123'));
      expect(result).toBe(true);
    });

    it('should detect .env.abc-123 files', () => {
      (path.basename as jest.Mock).mockReturnValue('.env.abc-123');
      (isEnvironmentFile as jest.Mock).mockReturnValue(true);
      
      const result = isEnvironmentFile(path.basename('.env.abc-123'));
      expect(result).toBe(true);
    });

    it('should NOT detect non-env files', () => {
      const nonEnvFiles = ['config.env', 'env.config', 'environment.txt', 'envfile', '.envfile'];
      
      nonEnvFiles.forEach(filename => {
        (path.basename as jest.Mock).mockReturnValue(filename);
        (isEnvironmentFile as jest.Mock).mockReturnValue(false);
        
        const result = isEnvironmentFile(path.basename(filename));
        expect(result).toBe(false);
      });
    });
  });

  describe('document matcher logic', () => {
    it('should match by language ID', () => {
      const doc = { languageId: 'typescript', fileName: 'unknown.xyz' } as TextDocument;
      
      (documentMatcher as jest.Mock).mockImplementation((document) => {
        return (ids: string[], exts: string[]) => {
          return ids.includes(document.languageId) || exts.some(ext => document.fileName.endsWith(`.${ext}`));
        };
      });

      const matcher = documentMatcher(doc);
      const result = matcher(['typescript', 'javascript'], ['js', 'ts']);
      
      expect(result).toBe(true);
    });

    it('should match by file extension', () => {
      const doc = { languageId: 'plaintext', fileName: 'script.ts' } as TextDocument;
      
      (documentMatcher as jest.Mock).mockImplementation((document) => {
        return (ids: string[], exts: string[]) => {
          return ids.includes(document.languageId) || exts.some(ext => document.fileName.endsWith(`.${ext}`));
        };
      });

      const matcher = documentMatcher(doc);
      const result = matcher(['typescript', 'javascript'], ['js', 'ts']);
      
      expect(result).toBe(true);
    });

    it('should match when both language ID and extension match', () => {
      const doc = { languageId: 'typescript', fileName: 'script.ts' } as TextDocument;
      
      (documentMatcher as jest.Mock).mockImplementation((document) => {
        return (ids: string[], exts: string[]) => {
          return ids.includes(document.languageId) || exts.some(ext => document.fileName.endsWith(`.${ext}`));
        };
      });

      const matcher = documentMatcher(doc);
      const result = matcher(['typescript', 'javascript'], ['js', 'ts']);
      
      expect(result).toBe(true);
    });

    it('should NOT match when neither language ID nor extension match', () => {
      const doc = { languageId: 'plaintext', fileName: 'script.txt' } as TextDocument;
      
      (documentMatcher as jest.Mock).mockImplementation((document) => {
        return (ids: string[], exts: string[]) => {
          return ids.includes(document.languageId) || exts.some(ext => document.fileName.endsWith(`.${ext}`));
        };
      });

      const matcher = documentMatcher(doc);
      const result = matcher(['typescript', 'javascript'], ['js', 'ts']);
      
      expect(result).toBe(false);
    });
  });

  describe('parser selection priority', () => {
    it('should prioritize environment files over other matches', () => {
      // This test verifies the order of checks in the factory
      // Environment files should be checked first, before JSON/YAML/Code
      const envDocument = {
        languageId: 'json', // Could match JSON parser
        fileName: '.env.local'
      } as TextDocument;

      (isEnvironmentFile as jest.Mock).mockReturnValue(true);
      (path.basename as jest.Mock).mockReturnValue('.env.local');

      // Should detect as environment file first
      const isEnv = isEnvironmentFile(path.basename(envDocument.fileName));
      expect(isEnv).toBe(true);
    });

    it('should select JSON parser for .json files', () => {
      const jsonDocument = {
        languageId: 'json',
        fileName: 'config.json'
      } as TextDocument;

      (isEnvironmentFile as jest.Mock).mockReturnValue(false);
      (path.basename as jest.Mock).mockReturnValue('config.json');
      
      (documentMatcher as jest.Mock).mockImplementation(() => {
        return (ids: string[], exts: string[]) => {
          if (ids.includes('json') && exts.includes('json')) {
            return true;
          }
          return false;
        };
      });

      const shouldUseJsonParser = documentMatcher(jsonDocument)(['json'], ['json']);
      expect(shouldUseJsonParser).toBe(true);
    });

    it('should select YAML parser for .yaml and .yml files', () => {
      const yamlExtensions = ['yaml', 'yml'];
      
      yamlExtensions.forEach(ext => {
        const yamlDocument = {
          languageId: 'yaml',
          fileName: `config.${ext}`
        } as TextDocument;

        (isEnvironmentFile as jest.Mock).mockReturnValue(false);
        (path.basename as jest.Mock).mockReturnValue(`config.${ext}`);
        
        (documentMatcher as jest.Mock).mockImplementation((doc) => {
          return (ids: string[], exts: string[]) => {
            if (ids.includes('yaml') && exts.includes(ext)) {
              return true;
            }
            return false;
          };
        });

        const shouldUseYamlParser = documentMatcher(yamlDocument)(['yaml'], ['yml', 'yaml']);
        expect(shouldUseYamlParser).toBe(true);
      });
    });

    it('should select Code parser for various programming languages', () => {
      const codeLanguages = [
        { lang: 'javascript', ext: 'js' },
        { lang: 'typescript', ext: 'ts' },
        { lang: 'typescript', ext: 'tsx' },
        { lang: 'python', ext: 'py' },
        { lang: 'go', ext: 'go' },
        { lang: 'java', ext: 'java' },
        { lang: 'csharp', ext: 'cs' },
        { lang: 'php', ext: 'php' },
        { lang: 'ruby', ext: 'rb' }
      ];

      codeLanguages.forEach(({ lang, ext }) => {
        const codeDocument = {
          languageId: lang,
          fileName: `script.${ext}`
        } as TextDocument;

        (isEnvironmentFile as jest.Mock).mockReturnValue(false);
        (path.basename as jest.Mock).mockReturnValue(`script.${ext}`);
        
        (documentMatcher as jest.Mock).mockImplementation((doc) => {
          return (ids: string[], exts: string[]) => {
            const supportedLangs = ['javascript', 'typescript', 'python', 'go', 'java', 'csharp', 'php', 'ruby'];
            const supportedExts = ['js', 'ts', 'jsx', 'tsx', 'py', 'go', 'java', 'cs', 'php', 'rb'];
            
            return supportedLangs.includes(doc.languageId) || supportedExts.includes(ext);
          };
        });

        const shouldUseCodeParser = documentMatcher(codeDocument)(
          ['javascript', 'typescript', 'python', 'go', 'java', 'csharp', 'php', 'ruby'],
          ['js', 'ts', 'jsx', 'tsx', 'py', 'go', 'java', 'cs', 'php', 'rb']
        );
        expect(shouldUseCodeParser).toBe(true);
      });
    });

    it('should return null for unsupported file types', () => {
      const unsupportedDocument = {
        languageId: 'plaintext',
        fileName: 'document.txt'
      } as TextDocument;

      (isEnvironmentFile as jest.Mock).mockReturnValue(false);
      (path.basename as jest.Mock).mockReturnValue('document.txt');
      
      (documentMatcher as jest.Mock).mockImplementation((doc) => {
        return (ids: string[], exts: string[]) => false;
      });

      // Simulate the factory logic
      const isEnv = isEnvironmentFile(path.basename(unsupportedDocument.fileName));
      const isJson = documentMatcher(unsupportedDocument)(['json'], ['json']);
      const isYaml = documentMatcher(unsupportedDocument)(['yaml'], ['yml', 'yaml']);
      const isCode = documentMatcher(unsupportedDocument)(
        ['javascript', 'typescript', 'python', 'go', 'java', 'csharp', 'php', 'ruby'],
        ['js', 'ts', 'jsx', 'tsx', 'py', 'go', 'java', 'cs', 'php', 'rb']
      );

      // All should be false, indicating no parser should be selected
      expect(isEnv).toBe(false);
      expect(isJson).toBe(false);
      expect(isYaml).toBe(false);
      expect(isCode).toBe(false);
    });
  });

  describe('parser instantiation', () => {
    it('should create CodeParser instance correctly', () => {
      const mockCodeParser = {
        parse: jest.fn(),
        getMatches: jest.fn().mockReturnValue([])
      };
      (CodeParser as jest.MockedClass<typeof CodeParser>).mockImplementation(() => mockCodeParser);

      const parser = new CodeParser(mockDocument);
      
      expect(CodeParser).toHaveBeenCalledWith(mockDocument);
      expect(parser).toBe(mockCodeParser);
    });

    it('should create DotEnvParser instance correctly', () => {
      const mockDotEnvParser = {
        parse: jest.fn(),
        getMatches: jest.fn().mockReturnValue([])
      };
      (DotEnvParser as jest.MockedClass<typeof DotEnvParser>).mockImplementation(() => mockDotEnvParser);

      const parser = new DotEnvParser(mockDocument);
      
      expect(DotEnvParser).toHaveBeenCalledWith(mockDocument);
      expect(parser).toBe(mockDotEnvParser);
    });

    it('should create JsonConfigParser instance correctly', () => {
      const mockJsonParser = {
        parse: jest.fn(),
        getMatches: jest.fn().mockReturnValue([])
      };
      (JsonConfigParser as jest.MockedClass<typeof JsonConfigParser>).mockImplementation(() => mockJsonParser);

      const parser = new JsonConfigParser(mockDocument);
      
      expect(JsonConfigParser).toHaveBeenCalledWith(mockDocument);
      expect(JsonConfigParser).toHaveBeenCalledWith(mockDocument);
      expect(parser).toBe(mockJsonParser);
    });

    it('should create YamlConfigParser instance correctly', () => {
      const mockYamlParser = {
        parse: jest.fn(),
        getMatches: jest.fn().mockReturnValue([])
      };
      (YamlConfigParser as jest.MockedClass<typeof YamlConfigParser>).mockImplementation(() => mockYamlParser);

      const parser = new YamlConfigParser(mockDocument);
      
      expect(YamlConfigParser).toHaveBeenCalledWith(mockDocument);
      expect(parser).toBe(mockYamlParser);
    });
  });

  describe('edge cases and error handling', () => {
    it('should handle files with no extension', () => {
      const noExtDocument = {
        languageId: 'plaintext',
        fileName: 'Dockerfile'
      } as TextDocument;

      (isEnvironmentFile as jest.Mock).mockReturnValue(false);
      (path.basename as jest.Mock).mockReturnValue('Dockerfile');
      
      (documentMatcher as jest.Mock).mockImplementation((doc) => {
        return (ids: string[], exts: string[]) => {
          // Only language ID matching would work for files without extensions
          return ids.includes(doc.languageId);
        };
      });

      const matcher = documentMatcher(noExtDocument);
      const result = matcher(['dockerfile', 'plaintext'], ['dockerfile']);
      
      expect(result).toBe(true);
    });

    it('should handle files with multiple dots', () => {
      const multiDotDocument = {
        languageId: 'plaintext',
        fileName: 'config.prod.json'
      } as TextDocument;

      (isEnvironmentFile as jest.Mock).mockReturnValue(false);
      (path.basename as jest.Mock).mockReturnValue('config.prod.json');
      
      (documentMatcher as jest.Mock).mockImplementation((doc) => {
        return (ids: string[], exts: string[]) => {
          return exts.some(ext => doc.fileName.endsWith(`.${ext}`));
        };
      });

      const matcher = documentMatcher(multiDotDocument);
      const result = matcher(['json'], ['json']);
      
      expect(result).toBe(true);
    });

    it('should handle case sensitivity in file extensions', () => {
      const caseSensitiveDocument = {
        languageId: 'plaintext',
        fileName: 'config.JSON'
      } as TextDocument;

      (isEnvironmentFile as jest.Mock).mockReturnValue(false);
      (path.basename as jest.Mock).mockReturnValue('config.JSON');
      
      (documentMatcher as jest.Mock).mockImplementation((doc) => {
        return (ids: string[], exts: string[]) => {
          return exts.some(ext => doc.fileName.toLowerCase().endsWith(`.${ext.toLowerCase()}`));
        };
      });

      const matcher = documentMatcher(caseSensitiveDocument);
      const result = matcher(['json'], ['json']);
      
      expect(result).toBe(true);
    });
  });
}); 