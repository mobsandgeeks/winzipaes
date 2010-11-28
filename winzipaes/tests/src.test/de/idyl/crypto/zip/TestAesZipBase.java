package de.idyl.crypto.zip;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Date;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.Before;

import de.idyl.crypto.zip.impl.ExtZipEntry;

public class TestAesZipBase {

	static {
		System.setProperty("java.util.logging.config.file", "logging.properties");
	}

	public static void activateLog() {
		Logger logger = Logger.getLogger( AesZipFileDecrypter.class.getName() );
		logger.setLevel( Level.ALL );
		ConsoleHandler ch = new ConsoleHandler();
		logger.addHandler( ch );
		ch.setLevel(Level.ALL);
	}

	// --------------------------------------------------------------------------
	
	protected static final String PASSWORD = "12345678";
	
	// --------------------------------------------------------------------------
	
	protected final static String BASE_PATH = "tests";

	protected final static String IN_PATH = BASE_PATH + File.separator + "in";

	protected final static String IN_ZIP_PATH = IN_PATH + File.separator + "zip";
	
	protected final static String OUT_PATH = BASE_PATH + File.separator + "out";

	// --------------------------------------------------------------------------

	protected static FileInputStream getInFileAsStream( String name ) throws FileNotFoundException {
		return new FileInputStream( new File( IN_PATH + File.separator + name ) );
	}
	
	protected static File getInFile( String name ) {
		return new File( IN_PATH + File.separator + name );
	}

	protected static File getInZipFile( String name ) {
		return new File( IN_ZIP_PATH + File.separator + name );		
	}

	protected static File getOutFile( String name ) {
		return new File( OUT_PATH + File.separator + name );		
	}

	// --------------------------------------------------------------------------

	protected static boolean deleteDirectory(File path) {
		if (path.exists()) {
			File[] files = path.listFiles();
			for (int i = 0; i < files.length; i++) {
				if (files[i].isDirectory()) {
					deleteDirectory(files[i]);
				} else {
					files[i].delete();
				}
			}
		}
		return path.delete();
	}

	// --------------------------------------------------------------------------
	
	@Before
	public void cleanOut() {
		File out = new File( OUT_PATH );
		if( out.exists() ) {
			deleteDirectory( out );
		}
		out.mkdirs();
	}
	
	protected static void addZipEntry( String name, String content, ZipOutputStream zout ) throws IOException {
		ZipEntry ze = new ZipEntry(name);
		ze.setTime((new Date()).getTime());
		zout.putNextEntry(ze);
		zout.write(content.getBytes("iso-8859-1"));
		zout.closeEntry();
	}
	
	/** only checks for first line in file... */
	protected static void checkZipEntry( AesZipFileDecrypter aesDecryptor, String fileName, String fileContent, String password ) throws Exception {
		ExtZipEntry entry = aesDecryptor.getEntry(fileName);
		if( entry==null ) {
			throw new FileNotFoundException( fileName );
		}
		File decFile = getOutFile("extractedFile.txt");		
		aesDecryptor.extractEntry(entry, decFile, password);
		BufferedReader fr = new BufferedReader( new FileReader(decFile) );
		String line = fr.readLine();
		assertEquals( fileContent, line );
		decFile.delete();
	}
	
}
