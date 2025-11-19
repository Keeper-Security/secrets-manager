#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com

BLOB_HEADER = b"\xff\xff"  # Encrypted BLOB Header: U+FFFF is a non-character
UTF_8_ENCODING = "utf-8"
AES_256_GCM = "aes-256-gcm"
MD5_HASH = "md5"
HEX_DIGEST = "hex"
DEFAULT_JSON_INDENT = 4
