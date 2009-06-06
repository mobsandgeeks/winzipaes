package de.idyl.crypto.zip;

import java.io.File;

import junit.framework.TestCase;

public class TestAesZipFileDecrypter extends TestCase {

	static {
		System.setProperty("java.util.logging.config.file", "logging.properties");
	}

	protected final static String TEST_PATH = "tests/data/";
	
	public void test1FileInZipFile() throws Exception {
		String password = "123456";
		File aesFile = new File(TEST_PATH + "1winzipEncryptedFile.zip");

		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		
		TestAesZipFileEncrypter.checkZipEntry( aesDecryptor, "foo.txt", "This is the contents of file foo.txt - It should be long enough, so we really have some", password );
	}
	
	public void test2FilesInZipFile() throws Exception {
		String password = "123456";
		File aesFile = new File(TEST_PATH + "2winzipEncryptedFiles.zip");

		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		
		TestAesZipFileEncrypter.checkZipEntry( aesDecryptor, "foo.txt", "This is the contents of file foo.txt - It should be long enough, so we really have some", password );
		TestAesZipFileEncrypter.checkZipEntry( aesDecryptor, "bar.txt", "This is the contents of file bar.txt - It should be long enough, so we really have some", password );
	}

}
