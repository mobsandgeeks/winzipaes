package de.idyl.crypto.zip.impl;

/**
 * byte[] functionality
 *
 * @author <a href="mailto:olaf@merkert.de">Olaf Merkert</a>
 */
public class ByteArrayHelper {

  public static long byteArrayToLong(byte[] in) {
    long out = 0;
    for( int i=in.length-1; i>0; i-- ) {
      out |= in[i] & 0xff;
      out <<= 8;
    }
    out |= in[0] & 0xff;
    return out;
  }

  public static int byteArrayToInt(byte[] in) {
    int out = 0;
    for( int i=in.length-1; i>0; i-- ) {
      out |= (int)(in[i] & 0xff);
      out <<= 8;
    }
    out |= in[0] & 0xff;
    return out;
  }

  public static short byteArrayToShort(byte[] in) {
    short out = 0;
    for( int i=in.length-1; i>0; i-- ) {
      out |= in[i] & 0xff;
      out <<= 8;
    }
    out |= in[0] & 0xff;
    return out;
  }

	public static byte[] intToByteArray(int in) {
		byte[] out = new byte[4];

		out[0] = (byte)in;
		out[1] = (byte)(in >> 8);
		out[2] = (byte)(in >> 16);
		out[3] = (byte)(in >> 24);

		return out;
	}

	public static byte[] intToByteArray(int in,int outSize) {
		byte[] out = new byte[outSize];
		byte[] intArray = intToByteArray(in);
		for( int i=0; i<intArray.length && i<outSize; i++ ) {
			out[i] = intArray[i];
		}
		return out;
	}

	public static String toString( byte[] theByteArray ){
		StringBuffer theResult = new StringBuffer();
		for( int i=0; i<theByteArray.length; i++ ) {
			theResult.append( Integer.toHexString(theByteArray[i]&0xff) ).append(' ');
		}
		return theResult.toString();
	}

	public static boolean isEqual( byte[] first, byte[] second ) {
		boolean out = first!=null && second!=null && first.length==second.length;
		for( int i=0; out && i<first.length; i++ ) {
			if( first[i]!=second[i] ) {
				out = false;
			}
		}
		return out;
	}

}
