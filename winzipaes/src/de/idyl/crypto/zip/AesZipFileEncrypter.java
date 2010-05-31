package de.idyl.crypto.zip;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import de.idyl.crypto.zip.impl.AESEncrypter;
import de.idyl.crypto.zip.impl.AESEncrypterBC;
import de.idyl.crypto.zip.impl.ExtZipEntry;
import de.idyl.crypto.zip.impl.ExtZipOutputStream;
import de.idyl.crypto.zip.impl.ZipFileEntryInputStream;

/**
 * Create ZIP archive containing AES-256 encrypted entries.
 * <br>
 * One instance of this class represents one encrypted ZIP file, that can recevie
 * add() method calls that must be followed by one final call to close() to write
 * the final archive part and close the output stream.
 * 
 * TODO - support 128 + 192 keys
 * 
 * @author <a href="mailto:olaf@merkert.de">Olaf Merkert</a>
 */
public class AesZipFileEncrypter {

	private static final Logger LOG = Logger.getLogger(AesZipFileEncrypter.class.getName());

	// --------------------------------------------------------------------------

	protected ExtZipOutputStream zipOS;

	/**
	 * 
	 * @param pathName
	 *            to output zip file (aes encrypted zip file)
	 */
	public AesZipFileEncrypter(String pathName) throws IOException {
		zipOS = new ExtZipOutputStream(new File(pathName));
	}

	/**
	 * 
	 * @param outFile
	 *            output file (aes encrypted zip file)
	 */
	public AesZipFileEncrypter(File outFile) throws IOException {
		zipOS = new ExtZipOutputStream(outFile);
	}

	// --------------------------------------------------------------------------

	protected void add(ZipFile inFile, String password) throws IOException,
			UnsupportedEncodingException {
		ZipFileEntryInputStream zfe = new ZipFileEntryInputStream(inFile);
		Enumeration<? extends ZipEntry> en = inFile.entries();
		while (en.hasMoreElements()) {
			ZipEntry ze = en.nextElement();
			zfe.nextEntry(ze);
			add(ze, zfe, password);
		}
		zfe.close();
	}

	protected void add(ExtZipEntry zipEntry, InputStream zipData) throws IOException,
			UnsupportedEncodingException {
		zipOS.putNextEntry(zipEntry);

		byte[] data = new byte[1024];
		int read = zipData.read(data);
		while (read != -1) {
			zipOS.writeBytes(data, 0, read);
			read = zipData.read(data);
		}
	}

	/** TODO - zipEntry might use extended local header */
	protected void add(ZipEntry zipEntry, ZipFileEntryInputStream zipData, String password)
			throws IOException, UnsupportedEncodingException {
		AESEncrypter aesEncrypter = new AESEncrypterBC(password.getBytes("iso-8859-1"));

		ExtZipEntry entry = new ExtZipEntry(zipEntry.getName());
		entry.setMethod(zipEntry.getMethod());
		entry.setSize(zipEntry.getSize());
		entry.setCompressedSize(zipEntry.getCompressedSize() + 28);
		entry.setTime(zipEntry.getTime());
		entry.initEncryptedEntry();

		zipOS.putNextEntry(entry);
		/*
		 * ZIP-file data contains: 1. salt 2. pwVerification 3. encryptedContent 4.
		 * authenticationCode
		 */
		zipOS.writeBytes(aesEncrypter.getSalt());
		zipOS.writeBytes(aesEncrypter.getPwVerification());

		byte[] data = new byte[1024];
		int read = zipData.read(data);
		while (read != -1) {
			aesEncrypter.encrypt(data, read);
			zipOS.writeBytes(data, 0, read);
			read = zipData.read(data);
		}

		byte[] finalAuthentication = aesEncrypter.getFinalAuthentication();
		if (LOG.isLoggable(Level.FINE)) {
			LOG.fine("finalAuthentication=" + Arrays.toString(finalAuthentication) + " at pos="
					+ zipOS.getWritten());
		}

		zipOS.writeBytes(finalAuthentication);
	}

	// --------------------------------------------------------------------------

	protected void zip(File inFile, File outFile) throws IOException {
		FileInputStream fin = new FileInputStream(inFile);
		FileOutputStream fout = new FileOutputStream(outFile);
		ZipOutputStream zout = new ZipOutputStream(fout);

		zout.putNextEntry(new ZipEntry(inFile.getName()));
		byte[] buffer = new byte[1024];
		int len;
		while ((len = fin.read(buffer)) > 0) {
			zout.write(buffer, 0, len);
		}
		zout.closeEntry();

		zout.close();
		fin.close();
	}

	// --------------------------------------------------------------------------

	/**
	 * add one file to encrypted zip file
	 * 
	 * @param pathToFile
	 *            the file to add
	 * @param password
	 *            the password used for encryption
	 * @throws IOException
	 */
	public void add(File pathToFile, String password) throws IOException {
		File outZipFile = new File(pathToFile + ".zip");
		zip(pathToFile, outZipFile);
		addAll(outZipFile, password);
		outZipFile.delete();
	}

	// --------------------------------------------------------------------------

	/**
	 * Take all elements from zipFile and add them ENCRYPTED with password to the new zip file
	 * created with this instance. <br>
	 * Encrypted data of each file has the same size as the compressed data, though the file size is
	 * increased by 26 bytes for salt and pw-verification bytes.
	 * 
	 * @param pathToZipFile
	 *            provides zipFileEntries for encryption
	 * @param password
	 *            used to perform the encryption
	 * @throws IOException
	 */
	public void addAll(File pathToZipFile, String password) throws IOException {
		ZipFile zipFile = new ZipFile(pathToZipFile);
		add(zipFile, password);
		zipFile.close();
	}

	// --------------------------------------------------------------------------

	/**
	 * Client is required to call this method after he added all entries so the
	 * final archive part is written.
	 */
	public void close() throws IOException {
		zipOS.finish();
	}

	// --------------------------------------------------------------------------

	/**
	 * Simply zip + encrypt one "inFile" to one "outFile" useing "password".
	 */
	public static void zipAndEncrypt( File inFile, File outFile, String password ) throws IOException {
		AesZipFileEncrypter enc = new AesZipFileEncrypter(outFile);
		enc.add( inFile, password);
		enc.close();
	}

}
