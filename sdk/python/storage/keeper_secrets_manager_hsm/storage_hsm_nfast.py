# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2022 Keeper Security Inc.
# Contact: sm@keepersecurity.com

# Requires: Entrust nShield SDK (nCore API)
# Prerequisites: x86_64 Windows or Linux, nShield Security World 12.80 or later, user permissions to access kmdata files
# Supported Python version: Python 3.8.5 (part of Entrust nShield SDK)
# To use nShield Python 3 support with another version of Python 3, contact Entrust Support.
# Usage:
# /opt/nfast/python3/bin/python3 -m venv --copies venv
# . venv/bin/activate
# pip install /opt/nfast/python3/additional-packages/nfpython*.whl

import hashlib
import logging
import os
import json

import errno
from json import JSONDecodeError

from keeper_secrets_manager_core.storage import KeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.utils import ENCODING

try:
    import nfpython, nfkm
except ImportError as e:
    logging.getLogger(logger_name).error("Missing nCipher nShield HSM dependencies. To install missing packages run: \r\n"
                                            "pip3 install /opt/nfast/python3/additional-packages/nfpython*.whl\r\n")
    raise Exception("Missing import dependencies: nfpython")


HSM_BLOB_HEADER = b"\xff\xff" # Encrypted BLOB Header: U+FFFF is a noncharacter
HSM_CHUNK_SIZE = 8000

# Example usage:
# # /opt/nfast/bin/generatekey -b simple protect=module type=AES size=256 ident=ksm
# from keeper_secrets_manager_core import SecretsManager
# from keeper_secrets_manager_hsm.storage_hsm_nfast import HsmNfastKeyValueStorage
# config = HsmNfastKeyValueStorage('simple', 'ksm', 'client-config.json') # auto encrypt
# secrets_manager = SecretsManager(config=config)
# all_records = secrets_manager.get_secrets()

class HsmNfastKeyValueStorage(KeyValueStorage):
    """ HSM encrypted key value storage - using nCipher nShield HSM"""

    default_config_file_location = "client-config.json"

    def __init__(self, app_name: str, ident: str, config_file_location: str = None):
        self.default_config_file_location = config_file_location if config_file_location else os.environ.get("KSM_CONFIG_FILE",
            HsmNfastKeyValueStorage.default_config_file_location)
        self.hsm_app_name = app_name if app_name else os.environ.get("KSM_NFAST_APPNAME", '')
        self.hsm_ident = ident if ident else os.environ.get("KSM_NFAST_IDENT", '')
        self.conn = nfpython.connection(needworldinfo=True)
        self.key = self.__load_key()
        self.last_saved_config_hash = ""
        self.config = {}
        self.__load_config()

    def __load_key(self, module=0, private=True) -> nfpython.KeyID:
        appident = nfkm.KeyIdent(appname=self.hsm_app_name, ident=self.hsm_ident)
        keydata = nfkm.findkey(self.conn, appident)

        cmd = nfpython.Command(cmd="LoadBlob")
        if private:
            cmd.args.blob = keydata.privblob
        else:
            cmd.args.blob = keydata.pubblob
        cmd.args.module = module

        rep = self.conn.transact(cmd, ignorestatus=True)
        if rep.status != 'OK':
            logging.getLogger(logger_name).error("HSM Failed to load encryption keys. Status = " + rep.status)
            raise Exception("Failed to load encryption keys. " + str(rep.status))

        keyid = rep.reply.idka
        return keyid # nfpython.KeyID

    def __encrypt_buffer(self, message: str) -> bytes:
        blob = b"" + HSM_BLOB_HEADER

        c = nfpython.Command(["ChannelOpen"])
        c.args.module = 0
        c.args.type = "simple"
        c.args.flags |= "key_present"
        c.args.mode = "encrypt"
        c.args.mech = "any"
        c.args.key = self.key

        rep = self.conn.transact(c)
        channel = rep.reply.idch
        if rep.reply.flags.isset("new_iv_present"):
            mech = rep.reply.new_iv.mech.getvalue().to_bytes(2, byteorder='big')
            blob += len(mech).to_bytes(2, byteorder='big')
            blob += mech

            iv = rep.reply.new_iv.iv.iv.tobytes()
            blob += len(iv).to_bytes(2, byteorder='big')
            blob += iv

        ciphertext = b""
        c = nfpython.Command(["ChannelUpdate"])
        for chunk in (message[i:i+HSM_CHUNK_SIZE] for i in range(0, len(message), HSM_CHUNK_SIZE)):
            c.args.idch = channel
            c.args.input = nfpython.ByteBlock(chunk, fromraw=True)
            r = self.conn.transact(c)
            ciphertext += r.reply.output.tobytes()

        c.args.input = nfpython.ByteBlock()
        c.args.flags |= "final"
        r = self.conn.transact(c)
        ciphertext += r.reply.output.tobytes()

        blob += len(ciphertext).to_bytes(4, byteorder='big')
        blob += ciphertext
        return blob

    def __decrypt_buffer(self, blob: bytes) -> str:
        mech_val = b""
        iv_val = ""
        ciphertext = ""

        buf = blob[:2]
        if buf != HSM_BLOB_HEADER:
            return ""

        success = False
        buf = blob[2:4] # mech len
        if len(buf) == 2:
            buflen = int.from_bytes(buf, byteorder='big')
            buf = blob[4:4+buflen]
            if len(buf) == buflen:
                mech_val = buf[:]

                pos = 4 + buflen
                buf = blob[pos:pos+2] # iv len
                if len(buf) == 2:
                    buflen = int.from_bytes(buf, byteorder='big')
                    buf = blob[pos+2:pos+2+buflen]
                    if len(buf) == buflen:
                        iv_val = buf[:]

                        pos += 2 + buflen
                        buf = blob[pos:pos+4] # text len
                        if len(buf) == 4:
                            buflen = int.from_bytes(buf, byteorder='big')
                            buf = blob[pos+4:pos+4+buflen]
                            if len(buf) == buflen:
                                ciphertext = buf[:]

                                pos += 4 + buflen # EOF check
                                buf = blob[pos:pos+1]
                                if len(buf) == 0:
                                    success = True
        if not success:
            return ""

        c = nfpython.Command(["ChannelOpen"])
        c.args.module = 0
        c.args.type = "simple"
        c.args.flags |= "key_present"
        c.args.flags |= "given_iv_present"
        c.args.mode = "decrypt"
        c.args.mech = "any"
        c.args.key = self.key
        mech_int = int.from_bytes(mech_val, byteorder='big')
        mech = nfpython.Mech.names.get(mech_int, 0)
        iv = nfpython.ByteBlock(iv_val, fromraw=True)
        c.args.given_iv._fromdict({'mech': mech, 'iv': {'iv': iv}})

        rep = self.conn.transact(c)
        channel = rep.reply.idch

        plaintext = ""
        c = nfpython.Command(["ChannelUpdate"])
        for chunk in (ciphertext[i:i+HSM_CHUNK_SIZE] for i in range(0, len(ciphertext), HSM_CHUNK_SIZE)):
            c.args.idch = channel
            c.args.input = nfpython.ByteBlock(chunk, fromraw=True)
            r = self.conn.transact(c)
            try:
                output_bytes = r.reply.output.tobytes()
                plaintext += output_bytes.decode('utf8')
            except Exception:
                logging.getLogger(logger_name).error("Error decrypting config file. Try with different key.")
                raise Exception("Error decrypting config file ".format(self.default_config_file_location))

        c.args.input = nfpython.ByteBlock()
        c.args.flags |= "final"
        rep = self.conn.transact(c)
        plaintext += rep.reply.output.tobytes().decode('utf8')
        return plaintext

    def __load_config(self, module=0):
        self.create_config_file_if_missing()

        is_blob = False
        try:
            with open(self.default_config_file_location, "rb") as fh:
                header = fh.read(2)
                is_blob = (HSM_BLOB_HEADER == header)
        except Exception:
            pass

        try:
            # try to read plain JSON (unencrypted)
            config = None
            if not is_blob:
                with open(self.default_config_file_location, "r", encoding=ENCODING) as fh:
                    try:
                        config_data = fh.read()
                        config = json.loads(config_data)
                    except UnicodeDecodeError:
                        logging.getLogger(logger_name).error("Config file is not utf-8 encoded.")
                        raise Exception("{} is not a utf-8 encoded file".format(self.default_config_file_location))
                    except JSONDecodeError as err:
                        # If the JSON file was not empty, it's a legit JSON error. Throw an exception.
                        if config_data is not None and config_data.strip() != "":
                            raise Exception("{} may contain JSON format problems or is not utf-8 encoded"
                                            ": {}".format(self.default_config_file_location, err))
                        # If it was an empty file, overwrite with the JSON config
                        logging.getLogger(logger_name).warning("Looks like config file is empty.")
                        config = {}
                        self.save_storage(config)
                    except Exception as err:
                        logging.getLogger(logger_name).error("Config JSON has problems: {}".format(err))
                        if "codec" in str(err):
                            raise Exception("{} is not a utf-8 encoded file.".format(self.default_config_file_location))
                        raise err

            if config:
                # detected plaintext JSON config -> encrypt
                self.config = config
                self.__save_config() # save encrypted
                self.last_saved_config_hash = hashlib.md5(json.dumps(config, indent=4, sort_keys=True).encode()).hexdigest()
            else:
                # decrypt binary blob
                ciphertext: bytes = bytes()
                try:
                    with open(self.default_config_file_location, "rb") as fh:
                        ciphertext = fh.read()
                except Exception as e:
                    logging.getLogger(logger_name).error("Failed to load config file " + self.default_config_file_location)
                    raise Exception("Failed to load config file " + self.default_config_file_location)

                if len(ciphertext) == 0:
                    logging.getLogger(logger_name).warning("Empty config file " + self.default_config_file_location)

                config_json = self.__decrypt_buffer(ciphertext)
                try:
                    config = json.loads(config_json)
                    self.config = config
                    self.last_saved_config_hash = hashlib.md5(json.dumps(config, indent=4, sort_keys=True).encode()).hexdigest()
                except Exception as err:
                    logging.getLogger(logger_name).error("Config JSON has problems: {}".format(err))
                    raise err
        except IOError:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), self.default_config_file_location)

    def __save_config(self, updated_config:dict = {}, module=0, force=False):
        config = self.config if self.config else {}
        config_json:str = json.dumps(config, indent=4, sort_keys=True)
        config_hash = hashlib.md5(config_json.encode()).hexdigest()

        if updated_config:
            ucfg_json:str = json.dumps(updated_config, indent=4, sort_keys=True)
            ucfg_hash = hashlib.md5(ucfg_json.encode()).hexdigest()
            if ucfg_hash != config_hash:
                config_hash = ucfg_hash
                config_json = ucfg_json
                self.config = dict(updated_config)
                # self.last_saved_config_hash = config_hash # update after save - to allow for retries

        if not force and config_hash == self.last_saved_config_hash:
            logging.getLogger(logger_name).warning("Skipped config JSON save. No changes detected.")
            return

        self.create_config_file_if_missing()
        blob = self.__encrypt_buffer(config_json)
        with open(self.default_config_file_location, "wb") as write_file:
            write_file.write(blob)
        self.last_saved_config_hash = config_hash

    def decrypt_config(self, autosave: bool = True) -> str:
        ciphertext: bytes = bytes()
        plaintext: str = ""
        try:
            with open(self.default_config_file_location, "rb") as fh:
                ciphertext = fh.read()
            if len(ciphertext) == 0:
                logging.getLogger(logger_name).warning("Empty config file " + self.default_config_file_location)
                return ""
        except Exception as e:
            logging.getLogger(logger_name).error("Failed to load config file " + self.default_config_file_location)
            raise Exception("Failed to load config file " + self.default_config_file_location)

        try:
            plaintext = self.__decrypt_buffer(ciphertext)
            if len(plaintext) == 0:
                logging.getLogger(logger_name).error("Failed to decrypt config file " + self.default_config_file_location)
            elif autosave:
                with open(self.default_config_file_location, "w") as fh:
                    fh.write(plaintext)
        except Exception as err:
            logging.getLogger(logger_name).error("Failed to write decrypted config file " + self.default_config_file_location)
            raise Exception("Failed to write decrypted config file " + self.default_config_file_location)
        return plaintext

    def change_key(self, new_ident: str) -> bool:
        old_ident = self.hsm_ident
        old_key = self.key
        try:
            self.hsm_ident = new_ident
            self.key = self.__load_key()
            self.__save_config(force=True)
        except Exception as e:
            self.hsm_ident = old_ident
            self.key = old_key
            logging.getLogger(logger_name).error(f"Failed to change the key to '{new_ident}' for config '{self.default_config_file_location}'")
            raise Exception("Failed to change the key for " + self.default_config_file_location)
        return True

    def read_storage(self):
        if not self.config:
            self.__load_config()
        return dict(self.config)

    def save_storage(self, updated_config):
        self.__save_config(updated_config)

    def get(self, key: ConfigKeys):
        config = self.read_storage()
        return config.get(key.value)

    def set(self, key: ConfigKeys, value):
        config = self.read_storage()
        config[key.value] = value
        self.save_storage(config)
        return config

    def delete(self, key: ConfigKeys):
        config = self.read_storage()

        kv = key.value
        if kv in config:
            del config[kv]
            logging.getLogger(logger_name).debug("Removed key %s" % kv)
        else:
            logging.getLogger(logger_name).debug("No key %s was found in config" % kv)

        self.save_storage(config)
        return config

    def delete_all(self):
        self.read_storage()
        self.config.clear()
        self.save_storage(self.config)
        return dict(self.config)

    def contains(self, key: ConfigKeys):
        config = self.read_storage()
        return key.value in config

    def create_config_file_if_missing(self):
        if not os.path.exists(self.default_config_file_location):
            with open(self.default_config_file_location, "wb") as fh:
                blob = self.__encrypt_buffer("{}")
                fh.write(blob)

    def is_empty(self):
        config = self.read_storage()
        return not config
