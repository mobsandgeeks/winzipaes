package de.idyl.crypto.zip.impl;

/**
 * Decrypt.
 *
 * @author <a href="mailto:olaf@merkert.de">Olaf Merkert</a>
 */
public interface AESDecrypter {

	public void decrypt( byte[] in, int length );

	public byte[] getFinalAuthentication();

}
