package de.idyl.winzipaes.impl;

import static org.junit.Assert.*;

import org.junit.Test;

import de.idyl.winzipaes.impl.ByteArrayHelper;

public class ByteArrayHelperTest {

	@Test
	public void testByteArrayToLong() {
		byte[] in = new byte[] { 1,2,3,4,5,6,0,0 };
		assertEquals( 0x060504030201L, ByteArrayHelper.toLong( in ) );
	}

	@Test
	public void testByteArrayToInt() {
		byte[] in = new byte[] { 1,2,3,4 };
		assertEquals( 0x04030201, ByteArrayHelper.toInt( in ) );

		in = new byte[] { 1,2 };
		assertEquals( 0x0201, ByteArrayHelper.toInt( in ) );
	}

}
