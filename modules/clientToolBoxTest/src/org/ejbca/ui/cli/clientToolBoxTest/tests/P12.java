package org.ejbca.ui.cli.clientToolBoxTest.tests;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Parameters;

/**
 * <h1>
 * Creation of P12 files.
 * </h1><p>
 * Uses EJBCA WS to create P12 files
 * ({@link #getIt(String, String, String, String)}) to be used in a
 * {@link #commandExecution(String, String, String)} test. Also deletes a named
 * file ({@link #deleteFile(String)}) before the start of the test.
 * </p>
 * @author lars
 *
 */
public class P12 extends FixWithWS {

	private static void getIt(
			final String caName,
			final String password,
			final File keyDir,
			final int nr
			) throws Exception {
		keyDir.mkdir();
		for( int i=0; i<nr; i++ ) {
			final String name = "tester-"+Integer.toString(i);
			final UserDataVOWS user = new UserDataVOWS ();
			user.setUsername (name);
			user.setPassword (password);
			user.setClearPwd (false);
			user.setSubjectDN ("CN="+name+",C=SE");
			user.setCaName(caName);
			user.setEmail (null);
			user.setSubjectAltName (null);
			user.setStatus (UserDataVOWS.STATUS_NEW);
			user.setTokenType (UserDataVOWS.TOKEN_TYPE_P12);
			user.setEndEntityProfileName("EMPTY");
			user.setCertificateProfileName("ENDUSER");
			getWS().editUser(user);
			final KeyStore wsks = getWS().pkcs12Req(name, password, "null", "2048", "RSA");
			try ( final OutputStream os = new FileOutputStream(new File(keyDir,name+".p12")) ) {
				os.write(wsks.getRawKeystoreData());
			}
		}
	}
	/**
	 * <h5>
	 * File deletion.
	 * </h5><p>
	 * The argument is defined with a TestNG parameter that has the same name.
	 * </p>
	 * @param deleteFileBefore Name of the file to be deleted.
	 * @throws Exception
	 */
	@BeforeTest
	@Parameters({"deleteFileBefore"})
	public static void deleteFile(final String deleteFileBefore) throws Exception {
		if ( deleteFileBefore==null || deleteFileBefore.length()<1 ) {
			return;
		}
		final File file = new File(deleteFileBefore);
		if ( file.isFile() ) {
			file.delete();
		}
	}
	/**
	 * <h5>
	 * Creation of P12 files.
	 * </h5><p>
	 * Each argument is defined with a TestNG parameter that has the same name.
	 * </p>
	 * @param caName name of the CA that will sign the certificates for all created P12 files.
	 * @param password the password of the p12 files.
	 * @param keyDir the directory where the files will be stored.
	 * @param nr number of p12 files to be created.
	 * @throws Exception
	 */
	@BeforeTest(dependsOnMethods={"deleteFile"})
	@Parameters({"caName", "password", "keyDir", "nr"})
	public static void getIt(
			final String caName,
			final String password,
			final String keyDir,
			final String nr
			) throws Exception {
		getIt(caName, password, new File(keyDir), Integer.parseInt(nr));
	}
}
