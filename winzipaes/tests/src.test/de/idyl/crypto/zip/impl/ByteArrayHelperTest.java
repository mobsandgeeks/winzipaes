package de.idyl.crypto.zip.impl;

import static org.junit.Assert.*;

import org.junit.Test;


public class ByteArrayHelperTest {

	@Test
	public void testByteArrayToLong() {
		byte[] in = new byte[] { 1,2,3,4,5,6,0,0 };
		assertEquals( 0x060504030201L, ByteArrayHelper.byteArrayToLong( in ) );
	}

	@Test
	public void testByteArrayToInt() {
		byte[] in = new byte[] { 1,2,3,4 };
		assertEquals( 0x04030201, ByteArrayHelper.byteArrayToInt( in ) );

		in = new byte[] { 1,2 };
		assertEquals( 0x0201, ByteArrayHelper.byteArrayToInt( in ) );
	}

}
