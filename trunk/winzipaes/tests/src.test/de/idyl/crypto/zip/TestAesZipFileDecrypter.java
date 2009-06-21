package de.idyl.crypto.zip;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.zip.ZipException;

import org.junit.Test;

import de.idyl.crypto.zip.impl.ExtZipEntry;

public class TestAesZipFileDecrypter {

	static {
		System.setProperty("java.util.logging.config.file", "logging.properties");
	}

	protected final static String TEST_PATH = "tests/data/";
	
	@Test
	public void test1FileInZipFile() throws Exception {
		String password = "123456";
		File aesFile = new File(TEST_PATH + "1winzipEncryptedFile.zip");

		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		
		TestAesZipFileEncrypter.checkZipEntry( aesDecryptor, "foo.txt", "This is the contents of file foo.txt - It should be long enough, so we really have some", password );
	}
	
	@Test
	public void test2FilesInZipFile() throws Exception {
		String password = "123456";
		File aesFile = new File(TEST_PATH + "2winzipEncryptedFiles.zip");

		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		
		TestAesZipFileEncrypter.checkZipEntry( aesDecryptor, "foo.txt", "This is the contents of file foo.txt - It should be long enough, so we really have some", password );
		TestAesZipFileEncrypter.checkZipEntry( aesDecryptor, "bar.txt", "This is the contents of file bar.txt - It should be long enough, so we really have some", password );
	}

	@Test
	public void testModDateTime() throws ZipException, IOException {
		File aesFile = new File(TEST_PATH + "1winzipEncryptedFile.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();
		
		assertEquals( 1, list.size() );
		assertEquals( "31.05.2009 19:00:26", SimpleDateFormat.getDateTimeInstance().format(list.get(0).getTime()) );   
	}
	
}
