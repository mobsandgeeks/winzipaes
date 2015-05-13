@see http://www.winzip.com/aes_info.htm

crypto routines by http://www.bouncycastle.org/

This library only supports Win-Zip's 256-Bit AES mode. The code was developed to create encrypted ZIP files, that can be decrypted with a Win-Zip (at least version 9) client, which is a widely available MS-Windows application. Later, the ability to decrypt files was added.

You need a bouncycastle jar to build and run the binaries, e.g. lcrypto-jdk15.jar from [here](http://www.bouncycastle.org/latest_releases.html). Binaries are not provided, as this library is more for developers to extend than for "users to use".



&lt;hr/&gt;



Thanks to all contributors for their input (all listed under [people](http://code.google.com/p/winzipaes/people/list)).



&lt;hr/&gt;



The latest major change was the integration of a patch submitted by Matthew Dempsky enabling the usage of JCA instead of BC (bouncy castle) as "encryption engine". Unfortunately, because of a maximum key size of 128 bit in JRE's JCA implementation on Windows (see http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml), the API got slightly more complicated and now forces a client to choose between encryption/decryption via JCA or BC.



&lt;hr/&gt;



Since 2012-02-15 winzipaes is available via [Maven Central](http://search.maven.org/#search%7Cga%7C1%7Cwinzipaes). (not yet included are the fixes for [issue41](https://code.google.com/p/winzipaes/issues/detail?id=41), [issue43](https://code.google.com/p/winzipaes/issues/detail?id=43), [issue45](https://code.google.com/p/winzipaes/issues/detail?id=45), [issue50](https://code.google.com/p/winzipaes/issues/detail?id=50))