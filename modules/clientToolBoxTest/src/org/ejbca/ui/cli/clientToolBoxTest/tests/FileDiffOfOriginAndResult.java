/**
 * 
 */
package org.ejbca.ui.cli.clientToolBoxTest.tests;

import static org.testng.Assert.assertEquals;
import static se.primeKey.x509.StreamUtils.hash;

import java.io.FileInputStream;
import java.io.InputStream;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

/**
 * <h1>
 * Equality check of 2 files after clientToolBox command.
 * </h1><p>
 * The check ({@link #checkDecryptedData(String, String)}) is done after the
 * call too {@link #commandExecution(String, String, String)}.
 * </p>
 * @author lars
 *
 */
public class FileDiffOfOriginAndResult extends PKCS11HSMKeyToolTests {

	/**
	 * <h5>
	 * Checks whether 2 files are equal or not.
	 * </h5><p>
	 * Called after {@link #commandExecution(String, String, String)}.
	 * </p><p>
	 * Each argument is defined with a TestNG parameter that has the same name.
	 * </p>
	 * @param originalFile the original file
	 * @param resultFile a file expected to have the same contents as 'org'.
	 * @throws Exception
	 */
	@Test(dependsOnMethods = { "commandExecution" })
	@Parameters({"originalFile", "resultFile"})
	public static void checkDecryptedData(final String originalFile, final String resultFile) throws Exception {
		final byte orgHash[];
		try ( InputStream is = new FileInputStream(originalFile) ) {
			orgHash = hash(is);
		}
		final byte decrHash[];
		try( InputStream is = new FileInputStream(resultFile) ) {
			decrHash = hash(is);
		}
		assertEquals(decrHash, orgHash);
	}
}
