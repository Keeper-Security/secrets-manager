package com.keepersecurity.secretmanager.aws.kms;

public class Constants {

	public static final String RSA_2048 = "RSA_2048";
	public static final String RSA_4096 = "RSA_4096";
			  
	public static final String SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT";
	public static final String RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256";
	public static final String RSAES_OAEP_SHA_1 = "RSAES_OAEP_SHA_1";
	public static final String SM2PKE = "SM2PKE";
	
	public static final byte[] BLOB_HEADER = { (byte) 0xFF, (byte) 0xFF };
	public static final int BLOCK_SIZE = 16;
	public static final int KEY_SIZE = 32;
	public static final String AES_GCM = "AES/GCM/NoPadding";
	public static final String AES = "AES";
	public static final int GCM_TAG_LENGTH = 96;

}
