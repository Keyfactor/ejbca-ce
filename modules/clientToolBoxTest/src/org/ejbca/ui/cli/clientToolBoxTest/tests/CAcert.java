package org.ejbca.ui.cli.clientToolBoxTest.tests;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Parameters;

/**
 * <h1>
 * Creation of a file with CA certificate.
 * </h1><p>
 * Uses EJBCA WS to create a file with the CA certificate to be used in the
 * {@link #commandExecution(String, String, String)} test.
 * </p>
 * @author lars
 *
 */
public class CAcert extends FixWithWS {

	/**
	 * <h5>
	 * Creation of a CA certificate file.
	 * </h5><p>
	 * The argument is defined with a TestNG parameter that has the same name.
	 * </p>
	 * @param caName the EJBCA name of the CA.
	 * @throws Exception
	 */
	@BeforeTest
	@Parameters({"caName"})
	public static void getIt(final String caName) throws Exception {
		final byte certData[] = getWS().getLastCAChain(caName).get(0).getCertificateData();
		try( final OutputStream os = new FileOutputStream(caName+".cacert.pem") ) {
			final PrintWriter pw = new PrintWriter(os, true);
			pw.println("-----BEGIN CERTIFICATE-----");
			os.write( certData );
			os.flush();
			pw.println();
			pw.println("-----END CERTIFICATE-----");
		}
	}
}
