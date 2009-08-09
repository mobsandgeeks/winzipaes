package de.idyl.crypto.zip;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.Date;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.Test;

import de.idyl.crypto.zip.impl.ExtZipEntry;

public class TestAesZipFileEncrypter {

	static {
		System.setProperty("java.util.logging.config.file", "logging.properties");
	}

	protected void addZipEntry( String name, String content, ZipOutputStream zout ) throws IOException {
		ZipEntry ze = new ZipEntry(name);
		ze.setTime((new Date()).getTime());
		zout.putNextEntry(ze);
		zout.write(content.getBytes("iso-8859-1"));
		zout.closeEntry();
	}

	/** only checks for first line in file... */
	public static void checkZipEntry( AesZipFileDecrypter aesDecryptor, String fileName, String fileContent, String password ) throws Exception {
		ExtZipEntry entry = aesDecryptor.getEntry(fileName);
		if( entry==null ) {
			throw new FileNotFoundException( fileName );
		}
		File decFile = new File(TestAesZipFileDecrypter.TEST_PATH + "extractedFile.txt");		
		aesDecryptor.extractEntry(entry, decFile, password);
		BufferedReader fr = new BufferedReader( new FileReader(decFile) );
		String line = fr.readLine();
		assertEquals( fileContent, line );
		decFile.delete();
	}
	
	@Test
	public void testFilesInZipFile() throws Exception {
		String fileName1 = "file1.txt";
		String fileContent1 = "file1file1file1file1file1";
		String fileName2 = "file2.txt";
		String fileContent2 = "file2file2file2file2file2file2file2file2file2";
		String fileName3 = "foo\\file3.txt";
		String fileContent3 = "file3file3file3file3file3file3file3file3file3file3file3file3file3file3file3file3file3";

		File tmpFile = new File(TestAesZipFileDecrypter.TEST_PATH + "tmpFile.zip");
		ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(tmpFile));
		zout.setLevel(Deflater.BEST_COMPRESSION);
		addZipEntry(fileName1, fileContent1, zout);
		addZipEntry(fileName2, fileContent2, zout);
		addZipEntry(fileName3, fileContent3, zout);
		zout.flush();
		zout.finish();
		zout.close();

		String password = "123456";
		File aesFile = new File(TestAesZipFileDecrypter.TEST_PATH + "aesFile.zip");
		AesZipFileEncrypter aesEncryptor = new AesZipFileEncrypter(aesFile);
		aesEncryptor.addEncrypted(tmpFile, password);
		
		AesZipFileDecrypter aesDecrypter = new AesZipFileDecrypter(aesFile);
		
		checkZipEntry( aesDecrypter, fileName1, fileContent1, password );
		checkZipEntry( aesDecrypter, fileName2, fileContent2, password );
		checkZipEntry( aesDecrypter, fileName3, fileContent3, password );
		
		ExtZipEntry entry = aesDecrypter.getEntry(fileName3);
		File extractedFile = new File(entry.getName()); 
		aesDecrypter.extractEntry( entry, extractedFile, password);
		aesDecrypter.close();
		
		aesFile.delete();
		tmpFile.delete();
	}

}
