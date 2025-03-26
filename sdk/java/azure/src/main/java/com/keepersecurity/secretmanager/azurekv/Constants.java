package com.keepersecurity.secretmanager.azurekv;

public class Constants {

	public static final byte[] BLOB_HEADER = { (byte) 0xFF, (byte) 0xFF };
	public static final int BLOCK_SIZE = 16;
	public static final int KEY_SIZE = 32;
	public static final String AES_GCM = "AES/GCM/NoPadding";
	public static final String AES = "AES";
	public static final int GCM_TAG_LENGTH = 96;
	public static final String KSM_CONFIG_FILE = "KSM_CONFIG_FILE";
	public static final String  KSM_AZ_KEY_ID = "KSM_AZ_KEY_ID";
	public static final String  MD5  = "MD5";
}
