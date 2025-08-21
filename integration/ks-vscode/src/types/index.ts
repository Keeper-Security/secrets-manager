import { KEEPER_NOTATION_FIELD_TYPES } from '../utils/constants';

export interface IVaultFolder {
  folder_uid: string;
  name: string;
  parent_uid: string;
  flags?: string;
  folder_path?: string;
}

export interface IFolder {
  folderUid: string;
  name: string;
  parentUid: string;
  folderPath?: string;
}

export interface ICurrentStorage {
  folderUid: string;
  name: string;
  parentUid: string;
  folderPath?: string;
}

export interface IField {
  type: string;
  label: string;
  value: string[];
  fieldType?: KEEPER_NOTATION_FIELD_TYPES;
}

export interface ICliListCommandResponse {
  record_uid: string;
  title: string;
  type: string;
  shared: string;
}

export interface ICliListFolderResponse {
  folder_uid: string;
  name: string;
  parent_uid: string;
  flags?: string;
}
