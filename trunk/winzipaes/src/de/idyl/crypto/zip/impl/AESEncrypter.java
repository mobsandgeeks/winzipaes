package de.idyl.crypto.zip.impl;

/**
 * Encrypt.
 *
 * @author <a href="mailto:olaf@merkert.de">Olaf Merkert</a>
 */
public interface AESEncrypter {

	public void encrypt( byte[] in, int length );

	public byte[] getSalt();

	public byte[] getPwVerification();

	public byte[] getFinalAuthentication();

}
