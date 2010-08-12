package de.idyl.winzipaes.impl;

/**
 * Encrypt.
 *
 * @author olaf@merkert.de
 */
public interface AESEncrypter {

	public void encrypt( byte[] in, int length );

	public byte[] getSalt();

	public byte[] getPwVerification();

	public byte[] getFinalAuthentication();

}
