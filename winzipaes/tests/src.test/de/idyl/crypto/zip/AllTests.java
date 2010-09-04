package de.idyl.crypto.zip;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses( {
	TestAesZipFileEncrypter.class,	
	TestAesZipFileDecrypter.class	
})
public class AllTests {

}
