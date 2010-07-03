package de.idyl.crypto.zip;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import de.idyl.crypto.zip.impl.AESEncrypter;
import de.idyl.crypto.zip.impl.AESEncrypterBC;
import de.idyl.crypto.zip.impl.ExtZipEntry;
import de.idyl.crypto.zip.impl.ExtZipOutputStream;

/**
 * Create ZIP-Outputstream containing entries from an existing ZIP-File, but AES encrypted.
 * 
 * TODO - support 128 + 192 keys
 * 
 * @author olaf@merkert.de
 */
public class AesZipFileEncrypterNew {

	private static final Logger LOG = Logger.getLogger(AesZipFileEncrypter.class.getName());

	// --------------------------------------------------------------------------

	protected ExtZipOutputStream zipOS;

	/**
	 * 
	 * @param pathName
	 *            to output zip file (aes encrypted zip file)
	 */
	public AesZipFileEncrypterNew(String pathName) throws IOException {
		zipOS = new ExtZipOutputStream(new File(pathName));
	}

	/**
	 * 
	 * @param outFile
	 *            output file (aes encrypted zip file)
	 */
	public AesZipFileEncrypterNew(File outFile) throws IOException {
		zipOS = new ExtZipOutputStream(outFile);
	}

	// --------------------------------------------------------------------------

static String dumpHex(byte[] data) {
	return dumpHex(data, 0, data.length);
}
static String dumpHex(byte[] data, int off, int len) {
	String ret = "["+ len +"]=";
	for (int i=off; i<len; i++) {
		ret += Integer.toHexString(data[i]&0xff) +" ";
	}
	return ret;
}

	/** jlcooke */

	public void add(File file, String password)
			throws IOException, UnsupportedEncodingException {
		add(file.getPath(), new FileInputStream(file), password);
	}

	public void add(String name, InputStream is, String password)
			throws IOException, UnsupportedEncodingException {
		AESEncrypter aesEncrypter = new AESEncrypterBC(password.getBytes("iso-8859-1"));

		// Compress contents of inputStream and report on bytes read
		// we need to first compress to know details of entry
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		DeflaterOutputStream dos = new DeflaterOutputStream(bos, new Deflater(9,true), 8*1024);
		int read, inputLen=0;
		byte[] buf = new byte[8*1024];
		while ((read=is.read(buf)) > 0) {
			inputLen += read;
			dos.write(buf, 0, read);
		}
		dos.close();
		byte[] data = bos.toByteArray();

		ExtZipEntry entry = new ExtZipEntry(name);
		entry.setMethod(ZipEntry.DEFLATED);
		entry.setSize(inputLen);
		entry.setCompressedSize(data.length + 28);
		entry.setTime((new java.util.Date()).getTime());
		entry.initEncryptedEntry();

		zipOS.putNextEntry(entry);
		/*
		 * ZIP-file data contains: 1. salt 2. pwVerification 3. encryptedContent 4.
		 * authenticationCode
		 */
		zipOS.writeBytes(aesEncrypter.getSalt());
		zipOS.writeBytes(aesEncrypter.getPwVerification());

		aesEncrypter.encrypt(data, data.length);
		zipOS.writeBytes(data, 0, data.length);

		byte[] finalAuthentication = aesEncrypter.getFinalAuthentication();
		if (LOG.isLoggable(Level.FINE)) {
			LOG.fine("finalAuthentication=" + Arrays.toString(finalAuthentication) + " at pos="
					+ zipOS.getWritten());
		}

		zipOS.writeBytes(finalAuthentication);
	}

	// --------------------------------------------------------------------------

	protected void zip(final String name, InputStream is, OutputStream os) throws IOException {
		ZipOutputStream zout = new ZipOutputStream(os);
		zout.setLevel(9);

		zout.putNextEntry(new ZipEntry(name));
		byte[] buffer = new byte[8*1024];
		int len;
		while ((len=is.read(buffer)) > 0)
			zout.write(buffer, 0, len);
		zout.closeEntry();

		zout.close();
		is.close();
		os.close();
	}

	// --------------------------------------------------------------------------
	public void close() throws IOException {
		zipOS.finish();
		zipOS = null;
	}


	// --------------------------------------------------------------------------

	/** testcode + usage example */
	public static void main(String[] args) throws Exception {
		AesZipFileEncrypter enc = new AesZipFileEncrypter("doc/zipSpecificationAes.zip");
		enc.add(new File("doc/zipSpecification.txt"), "foo");
		enc.close();
	}

}