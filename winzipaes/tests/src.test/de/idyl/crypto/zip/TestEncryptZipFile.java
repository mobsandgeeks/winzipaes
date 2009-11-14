package de.idyl.crypto.zip;

import java.io.File;
import java.util.List;

import org.junit.Test;

import de.idyl.crypto.zip.impl.ExtZipEntry;

public class TestEncryptZipFile {

	static {
		System.setProperty("java.util.logging.config.file", "logging.properties");
	}

	public static String ZIP_FILE_NAME = "tests/data/moco.zip";

	public void testEncryptZipFile() throws Exception {
		AesZipFileEncrypter enc = new AesZipFileEncrypter(ZIP_FILE_NAME);
		enc.zipAndEncrypt(new File("tests/data/Charros.txt"), "moco");
		
		System.out.println("---success! ---");
	}

	public void testDecryptZipFile() throws Exception {
		AesZipFileDecrypter d = new AesZipFileDecrypter(new File(ZIP_FILE_NAME));

		List<ExtZipEntry> list = d.getEntryList();

		int n = list.size();

		for (int i = 0; i < n; i++) {
			ExtZipEntry entry = list.get(i);
			String name = entry.getName();
			System.out.println("name=" + name);
			d.extractEntry(entry, new File("C:/tmp/" + name), "moco");
		}

		System.out.println("---success! ---");
	}

}
