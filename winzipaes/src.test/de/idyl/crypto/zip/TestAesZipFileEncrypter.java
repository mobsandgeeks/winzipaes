package de.idyl.crypto.zip;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.Date;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import junit.framework.TestCase;
import de.idyl.crypto.zip.impl.ExtZipEntry;

public class TestAesZipFileEncrypter extends TestCase {

	protected void addZipEntry( String name, String content, ZipOutputStream zout ) throws IOException {
		ZipEntry ze = new ZipEntry(name);
		ze.setTime((new Date()).getTime());
		zout.putNextEntry(ze);
		zout.write(content.getBytes("iso-8859-1"));
		zout.closeEntry();
	}

	public void testTwoFilesInZipFile() throws Exception {
		System.setProperty("java.util.logging.config.file", "logging.properties");

		String tempFileName = "c:\\tmp\\temp.zip";
		String fileName1 = "file1.txt";
		String fileContnt1 = "file1file1file1file1file1file1file1file1file1file1file1file1file1";
		String fileName2 = "file2.txt";
		String fileContnt2 = "file2file2file2file2file2file2file2file2file2file2file2file2file2file2file2";
		String fileName3 = "file3.txt";
		String fileContnt3 = "file3file3file3file3file3file3file3file3file3file3file3file3file3file3file3file3file3";

		ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(tempFileName));
		zout.setLevel(Deflater.BEST_COMPRESSION);
		addZipEntry(fileName1, fileContnt1, zout);
		addZipEntry(fileName2, fileContnt2, zout);
		addZipEntry(fileName3, fileContnt3, zout);
		zout.flush();
		zout.finish();
		zout.close();

		String password = "123456";
		String aesFileName = "c:\\tmp\\aes.zip";
		AesZipFileEncrypter aesEncryptor = new AesZipFileEncrypter(aesFileName);
		aesEncryptor.addEncrypted(new File(tempFileName), password);

		AesZipFileDecrypter aesDecryptor = new AesZipFileDecrypter(new File(aesFileName));
		ExtZipEntry entry = aesDecryptor.getEntry(fileName3);
		String decryptedFileName = "C:/tmp/file3decrypted.zip";
		aesDecryptor.extractEntry(entry, new File(decryptedFileName),password);
		
		BufferedReader fr = new BufferedReader( new FileReader(decryptedFileName) );
		String line = fr.readLine();
		assertEquals( fileContnt3, line );
	}

}
