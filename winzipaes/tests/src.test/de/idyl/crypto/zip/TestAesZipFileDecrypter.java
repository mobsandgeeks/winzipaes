package de.idyl.crypto.zip;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipException;

import org.junit.Test;

import de.idyl.crypto.zip.impl.ExtZipEntry;

public class TestAesZipFileDecrypter {

	static {
		System.setProperty("java.util.logging.config.file", "logging.properties");
	}

	public final static String TEST_PATH = "tests/data/";
	
	@Test
	public void test1FileInZipFile() throws Exception {
		
		activateLog();
		
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

	@Test
	public void test7zip() throws Exception {
		String password = "123456789";
		
		File aesFile = new File(TEST_PATH + "7.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();
		
		aesDecryptor.extractEntry( list.get(0), new File(TEST_PATH + "test7.txt"), password );
	}

	public static void activateLog() {
		Logger logger = Logger.getLogger( AesZipFileDecrypter.class.getName() );
		logger.setLevel( Level.ALL );
		ConsoleHandler ch = new ConsoleHandler();
		logger.addHandler( ch );
		ch.setLevel(Level.ALL);
	}
	
	@Test
	public void testDnz() throws Exception {		
		
		activateLog();
		
		String password = "x123456789x";
		File aesFile = new File(TEST_PATH + "testDNZ.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();
		aesDecryptor.extractEntry( list.get(0), new File(TEST_PATH + "testDNZ.txt"), password );
	}
	
}
