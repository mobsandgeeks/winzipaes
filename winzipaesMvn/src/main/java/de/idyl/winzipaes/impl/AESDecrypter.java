package de.idyl.winzipaes.impl;

/**
 * Decrypt.
 *
 * @author olaf@merkert.de
 */
public interface AESDecrypter {

	public void decrypt( byte[] in, int length );

	public byte[] getFinalAuthentication();

}
