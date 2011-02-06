package de.idyl.crypto.zip;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.zip.ZipException;

import org.junit.Test;
import org.junit.runners.Suite.SuiteClasses;

import de.idyl.crypto.zip.impl.ExtZipEntry;

@SuiteClasses(TestAesZipFileDecrypter.class)
public class TestAesZipFileDecrypter extends TestAesZipBase {

	protected static boolean deleteDirectory(File path) {
    if( path.exists() ) {
      for( File file : path.listFiles() ) {
         if(file.isDirectory()) {
           deleteDirectory(file);
         }
         else {
           file.delete();
         }
      }
    }
    return( path.delete() );
	}

	@Test
	public void testIsAesEncrypted() throws Exception {
		File aesFile = getInZipFile("1winzipEncryptedFile.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		ExtZipEntry entry = aesDecryptor.getEntry("foo.txt");
		assertTrue( entry.isAesEncrypted() );
	}
	
	@Test
	public void test1FileInZipFile() throws Exception {
		String password = "123456";
		File aesFile = getInZipFile("1winzipEncryptedFile.zip");

		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		
		checkZipEntry( aesDecryptor, "foo.txt", "This is the contents of file foo.txt - It should be long enough, so we really have some", password );
	}
	
//	@Test
//	public void test1FileInZipFileWithTmpFile() throws Exception {
//		String password = "123456";
//		File aesFile = getInZipFile("1winzipEncryptedFile.zip");
//
//		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
//		
//		checkZipEntry( aesDecryptor, "foo.txt", "This is the contents of file foo.txt - It should be long enough, so we really have some", password );
//	}
	
	@Test
	public void test2FilesInZipFile() throws Exception {
		String password = "123456";
		File aesFile = getInZipFile("2winzipEncryptedFiles.zip");

		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		
		checkZipEntry( aesDecryptor, "foo.txt", "This is the contents of file foo.txt - It should be long enough, so we really have some", password );
		checkZipEntry( aesDecryptor, "bar.txt", "This is the contents of file bar.txt - It should be long enough, so we really have some", password );
	}

	@Test
	public void testModDateTime() throws ZipException, IOException {
		File aesFile = getInZipFile("1winzipEncryptedFile.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();
		
		assertEquals( 1, list.size() );
		assertEquals( "31.05.2009 19:00:26", SimpleDateFormat.getDateTimeInstance().format(list.get(0).getTime()) );   
	}

	@Test
	public void test7zip() throws Exception {
		String password = "123456789";
		
		File aesFile = getInZipFile("7.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();
		
		aesDecryptor.extractEntryWithTmpFile( list.get(0), getOutFile("test7.txt"), password );
	}

	@Test
	public void testDnz() throws Exception {		
		//activateLog();
		String password = "x123456789x";
		File aesFile = getInZipFile("testDNZ.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();
		aesDecryptor.extractEntryWithTmpFile( list.get(0), getOutFile("testDNZ.txt"), password );
	}
	
	@Test
	public void testWithUnEncryptedEntries() throws Exception {		
		//activateLog();
		String password = "foobar";
		File aesFile = getInZipFile("mixed.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();		
		aesDecryptor.extractEntryWithTmpFile( list.get(0), getOutFile("bar"), password );
	}

	@Test(expected=ZipException.class)
	public void testWithUnEncryptedEntriesExExpected() throws Exception, ZipException {		
		//activateLog();
		String password = "foobar";
		File aesFile = getInZipFile("mixed.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();		
		aesDecryptor.extractEntryWithTmpFile( list.get(1), getOutFile("foo"), password );
	}
	
	@Test
	public void testWithSubdirs() throws Exception {		
		activateLog();
		String password = "foobar";
		File aesFile = getInZipFile("subdir.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();
		aesDecryptor.extractEntryWithTmpFile( list.get(1), getOutFile("bar"), password );
	}
	
	@Test
	public void testIssue2() throws Exception {
		String password = "test1234";
		File aesFile = getInZipFile("issue2.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();		
		//aesDecryptor.extractEntry( list.get(0), new File(TEST_OUT_PATH + "file1.txt"), password );
		// entry 1 is a directory
		aesDecryptor.extractEntryWithTmpFile( list.get(2), getOutFile("dir1/file2.txt"), password );		
	}

	@Test
	public void testZipFileWithComment() throws Exception {
		String password = "PASSWORD";
		File aesFile = getInZipFile("Test_ENDSIG.zip");
		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(aesFile);
		List<ExtZipEntry> list = aesDecryptor.getEntryList();		
		aesDecryptor.extractEntryWithTmpFile( list.get(0), getOutFile("Test_ENDSIG"), password );		
	}
	
}
