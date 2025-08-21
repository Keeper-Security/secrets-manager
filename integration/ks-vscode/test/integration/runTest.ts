import * as path from 'path';
import { runTests } from '@vscode/test-electron';
import * as fs from 'fs';

async function main() {
  try {
    // The folder containing the Extension Manifest package.json
    // Since this script runs from out/test/integration/, we need to go up 3 levels
    const extensionDevelopmentPath = path.resolve(__dirname, '../../../');

    // The path to the extension test runner script
    const extensionTestsPath = path.resolve(__dirname, './suite/index');

    // Ensure the extension is compiled and available
    const distPath = path.resolve(extensionDevelopmentPath, 'dist');
    const outDistPath = path.resolve(extensionDevelopmentPath, 'out/dist');
    
    // Create out/dist directory if it doesn't exist
    if (!fs.existsSync(outDistPath)) {
      fs.mkdirSync(outDistPath, { recursive: true });
    }
    
    // Copy the compiled extension to out/dist for tests to find
    const sourceFile = path.join(distPath, 'extension.js');
    const targetFile = path.join(outDistPath, 'extension.js');
    
    console.log(`Looking for source file at: ${sourceFile}`);
    console.log(`Will copy to target file at: ${targetFile}`);
    
    if (fs.existsSync(sourceFile)) {
      fs.copyFileSync(sourceFile, targetFile);
      console.log(`Successfully copied extension from ${sourceFile} to ${targetFile}`);
    } else {
      console.log(`Source extension file not found at ${sourceFile}`);
      // Check what's actually in the dist directory
      if (fs.existsSync(distPath)) {
        const files = fs.readdirSync(distPath);
        console.log(`Files in dist directory: ${files.join(', ')}`);
      } else {
        console.log(`Dist directory does not exist at: ${distPath}`);
      }
    }

    // Download VS Code, unzip it and run the integration test
    await runTests({ 
      extensionDevelopmentPath, 
      extensionTestsPath,
      launchArgs: ['--disable-extensions']
    });
  } catch (err) {
    console.error(err);
    console.error('Failed to run tests');
    process.exit(1);
  }
}

main();
