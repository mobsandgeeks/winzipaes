package de.idyl.winzipaes;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses( {
	TestAesZipFileEncrypter.class,	
	TestAesZipFileDecrypter.class,
	TestIssues.class
})
public class AllTests {

}
