package de.idyl.crypto.zip;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.List;

import org.junit.Test;

import de.idyl.crypto.zip.impl.ExtZipEntry;

public class TestIssues extends TestAesZipBase {

	@Test
	public void testIssue21() throws Exception {
		File inFile = getInZipFile("issue21.zip");
		File encFile = getOutFile("issue21outA.zip");
		AesZipFileEncrypter enc = new AesZipFileEncrypter(encFile);
    enc.addAll(inFile, "abcdef");
    enc.close();
    issue21Decrypt(encFile);

		encFile = getOutFile("issue21outB.zip");
    AesZipFileEncrypter.zipAndEncryptAll( inFile, encFile, "abcdef" );
    issue21Decrypt(encFile);

    cleanOut();
	}
	
	protected void issue21Decrypt(File encFile) throws Exception {
		AesZipFileDecrypter dec = new AesZipFileDecrypter(encFile);    
		List<ExtZipEntry> list = dec.getEntryList();
    for (int i=0; i<list.size(); i++){
      ExtZipEntry entry = list.get(i);
      String name = entry.getName();
      if( !entry.isDirectory() ) {
      	dec.extractEntry( entry, getOutFile(name), "abcdef" );
      }
    }
    
    dec.close();		
	}

	@Test
	public void testIssue21b() throws Exception {
		issue21Decrypt( getInZipFile("issue21b.zip") );
	}

	@Test
	public void testIssue18_10() throws Exception {
		File zipFile = getOutFile("issu18_10_out.zip");
		AesZipFileEncrypter enc = new AesZipFileEncrypter(zipFile);
		File inFile = getInZipFile("issue18_10.zip");
		enc.addAll(inFile, PASSWORD);
		enc.close();

		AesZipFileDecrypter dec = new AesZipFileDecrypter(zipFile);
		List<ExtZipEntry> entryList = dec.getEntryList();
		assertNotNull(entryList);
		assertFalse(entryList.isEmpty());
		
		ExtZipEntry entry = entryList.get(0);
		File extFile = getOutFile(entry.getName());
		dec.extractEntry(entry, extFile, PASSWORD);
	}

}
