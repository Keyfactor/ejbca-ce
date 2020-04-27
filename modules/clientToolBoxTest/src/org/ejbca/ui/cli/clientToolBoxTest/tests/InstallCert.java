package org.ejbca.ui.cli.clientToolBoxTest.tests;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import se.primeKey.pkcs11.Token;
import se.primeKey.x509.CertUtils;

/**
 * <h1>
 * Test of the 'installcert' command.
 * </h1><p>
 * Before the test a certificate is created from a previous fetch CSR of the
 * key ({@link #signCSRwithNewRootAndStoreCert(String, String, String)}).
 * </p><p>
 * The certificate chain for the key is then installed with the 'installcert'
 * command ({@link #commandExecution(String, String, String)}.
 * </p><p>
 * After the installation the installed certificate chain is retrieved from
 * the key entry. It is then tested that the retrieved chain equals the original
 * chain ({@link #checkInstalledCert(String, String)}.
 * </p>
 * @author lars
 *
 */
public class InstallCert extends PKCS11HSMKeyToolTests {

	/**
	 * <h5>
	 * Signing of a CSR and then storing the resulting certificate on file.
	 * </h5><p>
	 * Called after the {@link #commandExecution(String, String, String)} with
	 * 'certreq'.
	 * A CSR is signed with a private key that has the alias
	 * 'newRootEntryAlias'. The resulting certificate is stored on file.
	 * </p><p>
	 * Each argument is defined with a TestNG parameter that has the same name.
	 * </p>
	 * @param csrFile the CSR
	 * @param certFile name of the file to which the created certificate should be stored.
	 * @param newRootEntryAlias the alias in token 1 of the private key that will sign the CSR.
	 * @throws Exception
	 */
	@Parameters({"csrFile", "certFile", "newRootEntryAlias"})
	@BeforeTest
	public static void signCSRwithNewRootAndStoreCert(final String csrFile, final String certFile, final String newRootEntryAlias) throws Exception {
		final Token token = tokenObject.p11m.getToken(tokenObject.tokenInfo1.label, tokenObject.tokenInfo1.userPass);
		final PrivateKeyEntry entry = (PrivateKeyEntry)token.getEntry(newRootEntryAlias);
		final X509Certificate[] theCertificate;
		try ( final InputStream is = new FileInputStream(csrFile) ) {
			theCertificate = CertUtils.signCertificate(is, entry, false, token.provider, "SHA256WithRSA");
		}
		CertUtils.storeCertificates(theCertificate, certFile);
	}

	/**
	 * <h5>
	 * Test of the installed certificate chain.
	 * </h5><p>
	 * Called after the {@link #commandExecution(String, String, String)} with
	 * 'installcert'.
	 * The installed certificate chain of the entry is compared against the 
	 * certificate chain in the file given as argument to 'installcert'.
	 * </p><p>
	 * Each argument is defined with a TestNG parameter that has the same name.
	 * </p>
	 * @param keyAlias
	 * @param certFile
	 * @throws Exception
	 */
	@Test(dependsOnMethods = { "commandExecution" })
	@Parameters({"keyAlias", "certFile"})
	public static void checkInstalledCert(final String keyAlias, final String certFile) throws Exception {
		final Token token = tokenObject.p11m.getToken(tokenObject.tokenInfo2.label, tokenObject.tokenInfo2.userPass);
		final PrivateKeyEntry entry = (PrivateKeyEntry)token.getEntry(keyAlias);
		final Collection<? extends Certificate> cPemChain;
		try ( final InputStream is = new FileInputStream(certFile) ) {
			cPemChain = CertificateFactory.getInstance("X.509").generateCertificates(is);
		}
		final X509Certificate p11chain[] = (X509Certificate[])entry.getCertificateChain();
		final X509Certificate pemChain[] = cPemChain.toArray(new X509Certificate[cPemChain.size()]);

		assertEquals(p11chain.length, 2);
		assertNull( CertUtils.checkChain(p11chain, null) );
		assertEquals(p11chain, pemChain);
	}
}
