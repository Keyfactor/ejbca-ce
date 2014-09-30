/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;

import org.bouncycastle.cert.X509CRLHolder;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.request.CVCRequestMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.junit.Test;

/** JUnit test for CVC EAC CA
 * 
 * @version $Id$
 */
public class CVCCATest {

	public static final String CADN = "CN=CAREF001,C=SE";
	
	public CVCCATest() {
		CryptoProviderTools.installBCProvider();
	}
	
	@Test
	public void testCABasicOperations() throws Exception {
	    final CryptoToken cryptoToken = getNewCryptoToken();
	    CvcCA cvcca = createTestCA(cryptoToken, CADN);
        Certificate cacert = cvcca.getCACertificate();
        
        // Start by creating a PKCS7, should return null for CVC CA
        byte[] p7 = cvcca.createPKCS7(cryptoToken, cacert, true);
        assertNull(p7);
        
		// Create a certificate request (will be CVC)
        byte[] req = cvcca.createRequest(cryptoToken, null, "SHA1WithRSA", cacert, CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        CVCRequestMessage msg = new CVCRequestMessage(req);
        assertNotNull(msg);
        assertEquals(CADN, msg.getRequestDN());
        // There are no such things as request extensions in CVC requests, so we don't have to bother with testing 
        // of the "attributes" parameter to createRequest 
        
        // Generate a client certificate and check that it was generated correctly
        EndEntityInformation user = new EndEntityInformation("username", "CN=User001,C=SE", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = cvcca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        assertNotNull(usercert);
        assertEquals("CN=User001,C=SE", CertTools.getSubjectDN(usercert));
        assertEquals(CADN, CertTools.getIssuerDN(usercert));
        assertEquals("SHA256WITHRSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(usercert));
        // No such things as key identifiers or extensions in CVC certificates
        assertNull(CertTools.getSubjectKeyId(cacert));
        assertEquals("", CertTools.getSubjectAlternativeName(usercert));
        assertNull(CertTools.getUPNAltName(usercert));
        assertFalse(CertTools.isSelfSigned(usercert));
        usercert.verify(cryptoToken.getPublicKey(cvcca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)));
        usercert.verify(cvcca.getCACertificate().getPublicKey());
        assertTrue(CertTools.isCA(cvcca.getCACertificate()));
        assertFalse(CertTools.isCA(usercert));
        
        // Create a CRL, does not exist for CVC CAs so will return null
        Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
        X509CRLHolder crl = cvcca.generateCRL(cryptoToken, revcerts, 1);
        assertNull(crl);
	}
	

	@Test
	public void testStoreAndLoad() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        CvcCA ca = createTestCA(cryptoToken, CADN);
		
        EndEntityInformation user = new EndEntityInformation("username", "CN=User001,C=SE", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate usercert = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        PublicKey publicKey = cryptoToken.getPublicKey(ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        String keyhash = CertTools.getFingerprintAsString(publicKey.getEncoded());
        usercert.verify(publicKey);

        // Save CA data
		Object o = ca.saveData();
		
		// Restore CA from data (and other things)
		@SuppressWarnings("unchecked")
		CvcCA ca1 = CvcCA.getInstance((HashMap<Object, Object>)o, 777, CADN, "test", CAConstants.CA_ACTIVE, new Date());

		Certificate usercert1 = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        PublicKey publicKey1 = cryptoToken.getPublicKey(ca1.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        String keyhash1 = CertTools.getFingerprintAsString(publicKey1.getEncoded());
        assertEquals(keyhash, keyhash1);
        usercert1.verify(publicKey);
        usercert.verify(publicKey1);
        usercert1.verify(publicKey1);
        
        final CAInfo caInfo = ca.getCAInfo();
        CAData cadata = new CAData(caInfo.getSubjectDN(), caInfo.getName(), caInfo.getStatus(), ca);

        CA ca2 = cadata.getCA();
		Certificate usercert2 = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        PublicKey publicKey2 = cryptoToken.getPublicKey(ca2.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        String keyhash2 = CertTools.getFingerprintAsString(publicKey2.getEncoded());
        assertEquals(keyhash, keyhash2);
        usercert2.verify(publicKey);
        usercert2.verify(publicKey1);
        usercert2.verify(publicKey2);
        
        // Check CAinfo and CAtoken
        final CAInfo caInfo1 = ca.getCAInfo();
        final CAToken caToken1 = caInfo1.getCAToken();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, caToken1.getSignatureAlgorithm());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, caToken1.getEncryptionAlgorithm());
        assertEquals(SoftCryptoToken.class.getName(), cryptoToken.getClass().getName());
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, caToken1.getKeySequenceFormat());
        
        final CAInfo caInfo2 = ca2.getCAInfo();
        final CAToken caToken2 = caInfo2.getCAToken();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, caToken2.getSignatureAlgorithm());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, caToken2.getEncryptionAlgorithm());
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, caToken2.getKeySequenceFormat());
	}

	private static CvcCA createTestCA(CryptoToken cryptoToken, String cadn) throws Exception {
		// Create catoken
		Properties caTokenProperties = new Properties();
    	caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
    	caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS); 
    	caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        // Set key generation property, since we have no old keys to generate the same sort
        cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATESIGNKEYALIAS);
        cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATEDECKEYALIAS);
        
		CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
		// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
		catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
		catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
		catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
		catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // No extended services
        CVCCAInfo cainfo = new CVCCAInfo(cadn, "TEST", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 3650, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CVC CA");
        CvcCA cvcca = CvcCA.getInstance(cainfo);
        cvcca.setCAToken(catoken);
        // A CA certificate
        CAReferenceField caRef = new CAReferenceField("SE", "CAREF001", "00000");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "CAREF001", "00000");
        final PublicKey publicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        final PrivateKey privateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        CVCertificate cv = CertificateGenerator.createTestCertificate(publicKey, privateKey, caRef, holderRef, "SHA256WithRSA", AuthorizationRoleEnum.CVCA);
        CardVerifiableCertificate cvccacert = new CardVerifiableCertificate(cv);
        Certificate cacert = cvccacert;
		assertNotNull(cacert);
        Collection<Certificate> cachain = new ArrayList<Certificate>();
        cachain.add(cacert);
        cvcca.setCertificateChain(cachain);
        // Now our CA should be operational
        return cvcca;
	}

    /** @return a new empty soft auto-activated CryptoToken */
    private CryptoToken getNewCryptoToken() {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo1234");
        CryptoToken cryptoToken;
        try {
            cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), cryptoTokenProperties, null, 17,
                    "CryptoToken's name");
        } catch (NoSuchSlotException e) {
            throw new RuntimeException("Attemped to create a slot for a soft crypto token, should not be able to happen", e);
        }
        return cryptoToken;
    }
}
