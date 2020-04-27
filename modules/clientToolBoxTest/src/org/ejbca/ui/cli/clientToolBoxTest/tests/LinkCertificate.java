package org.ejbca.ui.cli.clientToolBoxTest.tests;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import se.primeKey.x509.CertUtils;
import se.primeKey.x509.KeyEntryGenerator;

/**
 * <h1>
 * Test of the 'linkcertificate' command.
 * </h1><p>
 * Creates certificate and private key for the old and the new root CA
 * ({@link #prepare(String, String, String, String)}) before the
 * 'linkcertificate' command ({@link #commandExecution(String, String, String)})
 * is executed.
 * </p><p>
 * After the command the produced link certificate is validated
 * ({@link #checkLinkCert(String, String, String)}).
 * </p>
 * @author lars
 *
 */
public class LinkCertificate extends PKCS11HSMKeyToolTests {

	private static void writeChainToStream(final OutputStream os, final X509Certificate chain[]) throws Exception {
		for ( final X509Certificate cert : chain ) {
			os.write(cert.getEncoded());
		}
	}

	/**
	 * <h5>
	 * Creates 2 private keys with corresponding certificates on the HSM.
	 * </h5><p>
	 * 2 {@link PrivateKeyEntry} are created on the HSM.
	 * One entry is to be used as the old CA root and the other as the new CA
	 * root when testing the 'linkcert' command.
	 * </p><p>
	 * Each argument is defined with a TestNG parameter that has the same name.
	 * </p>
	 * @param oldRootEntryAlias the alias of the {@link PrivateKeyEntry} for the old root.
	 * @param oldRootCertFileName the name of the file that will contain the certificate for the old root.
	 * @param newRootEntryAlias the alias of the {@link PrivateKeyEntry} for the new root.
	 * @param newRootCertFileName the name of the file that will contain the certificate for the new root.
	 * @throws Exception
	 */
	@Parameters({"oldRootEntryAlias", "oldRootCertFileName", "newRootEntryAlias", "newRootCertFileName"})
	@BeforeTest
	public static void prepare(
			final String oldRootEntryAlias,
			final String oldRootCertFileName,
			final String newRootEntryAlias,
			final String newRootCertFileName) throws Exception {
		{// generate an old ca and store its certificate chain on file
			final KeyEntryGenerator keg = new KeyEntryGenerator("RSA", oldRootEntryAlias, null, true, "Sha512WithRSA", "2048");
			final X509Certificate chain[] = keg.generateKeyEntry(tokenObject.p11m.getToken(tokenObject.tokenInfo1.label, tokenObject.tokenInfo1.userPass));
			try ( final OutputStream os = new FileOutputStream(oldRootCertFileName) ) {
				writeChainToStream(os, chain);
			}
		}
		{// generate a new ca and store its certificate chain on file
			final KeyEntryGenerator keg = new KeyEntryGenerator("RSA", newRootEntryAlias, null, true, "Sha512WithRSA", "2048");
			final X509Certificate chain[] = keg.generateKeyEntry(tokenObject.p11m.getToken(tokenObject.tokenInfo1.label, tokenObject.tokenInfo1.userPass));
			try ( OutputStream os = new FileOutputStream(newRootCertFileName) ) {
				writeChainToStream(os, chain);
			}
		}
	}

	/**
	 * <h5>
	 * Test of a link certificate.
	 * </h5><p>
	 * This is tested:<ul>
	 * <li>Link certificate must be signed by the old root certificate.</li>
	 * <li>The issuer DN of the link certificate must be exactly the same as the subject DN of the old root certificate.</li>
	 * <li>Link certificate must have exactly the same subject DN as the old root certificate.</li>
	 * <li>Link certificate must have exactly the same basic constraints as the old root certificate.</li>
	 * <li>Link certificate must have exactly the same critical extensions as the old root certificate.</li>
	 * <li>Link certificate must have the non critical 'nameChange' extension.
	 * <li>Link certificate must have exactly the same non critical extensions as the old root certificate but for the added 'nameChange'.</li>
	 * <li>Link certificate must have exactly the same as the old root certificate.</li>
	 * </ul></p><p>
	 * Each argument is defined with a TestNG parameter that has the same name.
	 * </p>
	 * @param oldRootCertFileName the name of the file containing the old root certificate.
	 * @param newRootCertFileName the name of the file containing the new root certificate.
	 * @param linkCertFileName the name of the file containing a link certificate from the old root to the new root.
	 * @throws Exception
	 */
	@Parameters({"oldRootCertFileName", "newRootCertFileName", "linkCertFileName"})
	@Test(dependsOnMethods = { "commandExecution" })
	public static void checkLinkCert(
			final String oldRootCertFileName,
			final String newRootCertFileName,
			final String linkCertFileName) throws Exception {
		final X509Certificate oldCert;
		try ( final InputStream is = new FileInputStream(oldRootCertFileName) ) {
			oldCert = (X509Certificate)CertificateFactory.getInstance("X509").generateCertificate(is);
		}
		final X509Certificate newCert;
		try ( final InputStream is = new FileInputStream(newRootCertFileName) ) {
			newCert = (X509Certificate)CertificateFactory.getInstance("X509").generateCertificate(is);
		}
		final X509Certificate linkCert;
		try ( final InputStream is = new FileInputStream(linkCertFileName) ) {
			linkCert = (X509Certificate)CertificateFactory.getInstance("X509").generateCertificate(is);
		}
		final String sResult = CertUtils.checkChain(new X509Certificate[]{linkCert,oldCert}, null);
		assertNull(sResult, sResult);
		assertEquals(linkCert.getSubjectX500Principal(), newCert.getSubjectX500Principal());
		assertEquals(linkCert.getSubjectAlternativeNames(), newCert.getSubjectAlternativeNames());
		assertEquals(linkCert.getBasicConstraints(), newCert.getBasicConstraints());
		assertEquals(linkCert.getCriticalExtensionOIDs(), newCert.getCriticalExtensionOIDs());
		final Set<String> nonCriticalLinkCertOIDs = linkCert.getNonCriticalExtensionOIDs();
		assertTrue(nonCriticalLinkCertOIDs.remove("2.23.136.1.1.6.1"), "Name is changed from old to new so the linkcert must contain the 'nameChange' OID (2.23.136.1.1.6.1).");
		assertEquals(nonCriticalLinkCertOIDs, newCert.getNonCriticalExtensionOIDs());
		for ( final String oid : newCert.getNonCriticalExtensionOIDs() ) {
			if ( oid.equals("2.5.29.35") ) {
				continue;// AuthorityKeyIdentifier must be different.
			}
			assertEquals(linkCert.getExtensionValue(oid), newCert.getExtensionValue(oid), "OID "+oid+" differs.");
		}
		for ( final String oid : newCert.getCriticalExtensionOIDs() ) {
			assertEquals(linkCert.getExtensionValue(oid), newCert.getExtensionValue(oid), "OID "+oid+" differs.");
		}
	}
}
