import { Range, TextDocument } from 'vscode';

export interface ParserMatch {
  range: Range;
  fieldValue: string;
}

export abstract class Parser {
  protected matches: ParserMatch[] = [];

  public constructor(protected document: TextDocument) {}

  abstract parse(): void;

  public getMatches(): ParserMatch[] {
    this.parse();
    return this.matches;
  }
}
