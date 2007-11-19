package de.idyl.crypto.zip;

import java.io.File;

import junit.framework.TestCase;
import de.idyl.crypto.zip.impl.ExtZipEntry;


public class TestAesZipFileEncrypter extends TestCase {

	public void testEncryptDecrypt() throws Exception {
		System.err.println("Started");
		AesZipFileEncrypter zipEncrypter = new AesZipFileEncrypter( "doc/zipFormatSpecificationAES.zip" );
		zipEncrypter.addEncrypted( new File("doc/zipFormatSpecification.zip"), "foo" );

		AesZipFileDecrypter zipDecrypter = new AesZipFileDecrypter( new File("doc/zipFormatSpecificationAES.zip") );
		ExtZipEntry entry = zipDecrypter.getEntry( "zipFormatSpecification.txt" );
		System.err.println(entry);
		zipDecrypter.extractEntry( entry, new File("doc/foo.txt"), "foo" );
		//zipDecrypter.extractEntry( "doc/" , outFile, password)
		System.err.println("Finished");
	}

}
