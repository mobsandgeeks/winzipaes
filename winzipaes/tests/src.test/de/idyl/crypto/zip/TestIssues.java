package de.idyl.crypto.zip;

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
      dec.extractEntry( entry, getOutFile(name), "abcdef" );
    }
    dec.close();		
	}
	
}
