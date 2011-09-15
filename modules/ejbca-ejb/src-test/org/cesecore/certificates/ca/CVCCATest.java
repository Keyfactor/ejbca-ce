/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;

import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.request.CVCRequestMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;
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

/** JUnit test for X.509 CA
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
		
        CVCCA cvcca = createTestCA(CADN);
        Certificate cacert = cvcca.getCACertificate();
        
        // Start by creating a PKCS7, should return null for CVC CA
        byte[] p7 = cvcca.createPKCS7(cacert, true);
        assertNull(p7);
        
		// Create a certificate request (will be CVC)
        byte[] req = cvcca.createRequest(null, "SHA1WithRSA", cacert, CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        CVCRequestMessage msg = new CVCRequestMessage(req);
        assertNotNull(msg);
        assertEquals(CADN, msg.getRequestDN());
        // There are no such things as request extensions in CVC requests, so we don't have to bother with testing 
        // of the "attributes" parameter to createRequest 
        
        // Generate a client certificate and check that it was generated correctly
        EndEntityInformation user = new EndEntityInformation("username", "CN=User001,C=SE", 666, "rfc822Name=user@user.com", "user@user.com", EndEntityConstants.USER_ENDUSER, 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = cvcca.generateCertificate(user, keypair.getPublic(), 0, 10L, cp, "00000");
        assertNotNull(usercert);
        assertEquals("CN=User001,C=SE", CertTools.getSubjectDN(usercert));
        assertEquals(CADN, CertTools.getIssuerDN(usercert));
        assertEquals("SHA256WITHRSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(usercert));
        // No such things as key identifiers or extensions in CVC certificates
        assertNull(CertTools.getSubjectKeyId(cacert));
        assertEquals("", CertTools.getSubjectAlternativeName(usercert));
        assertNull(CertTools.getUPNAltName(usercert));
        assertFalse(CertTools.isSelfSigned(usercert));
        usercert.verify(cvcca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        usercert.verify(cvcca.getCACertificate().getPublicKey());
        assertTrue(CertTools.isCA(cvcca.getCACertificate()));
        assertFalse(CertTools.isCA(usercert));
        
        // Create a CRL, does not exist for CVC CAs so will return null
        Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
        CRL crl = cvcca.generateCRL(revcerts, 1);
        assertNull(crl);
	}
	

	@Test
	public void testStoreAndLoad() throws Exception {
		CVCCA ca = createTestCA(CADN);
		
        EndEntityInformation user = new EndEntityInformation("username", "CN=User001,C=SE", 666, "rfc822Name=user@user.com", "user@user.com", EndEntityConstants.USER_ENDUSER, 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate usercert = ca.generateCertificate(user, keypair.getPublic(), 0, 10L, cp, "00000");
        String keyhash = CertTools.getFingerprintAsString(ca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN).getEncoded());
        usercert.verify(ca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));

        // Save CA data
		Object o = ca.saveData();
		
		// Restore CA from data (and other things)
		CVCCA ca1 = new CVCCA((HashMap)o, 777, CADN, "test", CAConstants.CA_ACTIVE, new Date());

		Certificate usercert1 = ca.generateCertificate(user, keypair.getPublic(), 0, 10L, cp, "00000");
        String keyhash1 = CertTools.getFingerprintAsString(ca1.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN).getEncoded());
        assertEquals(keyhash, keyhash1);
        usercert1.verify(ca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        usercert.verify(ca1.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        usercert1.verify(ca1.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        
        CAInfo cainfo = ca.getCAInfo();
        CAData cadata = new CAData(cainfo.getSubjectDN(), cainfo.getName(), cainfo.getStatus(), ca);

        CA ca2 = cadata.getCA();
		Certificate usercert2 = ca.generateCertificate(user, keypair.getPublic(), 0, 10L, cp, "00000");
        String keyhash2 = CertTools.getFingerprintAsString(ca2.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN).getEncoded());
        assertEquals(keyhash, keyhash2);
        usercert2.verify(ca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        usercert2.verify(ca1.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        usercert2.verify(ca2.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        
        // Check CAinfo and CAtokeninfo
        cainfo = ca.getCAInfo();
        CATokenInfo catokeninfo = cainfo.getCATokenInfo();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, catokeninfo.getSignatureAlgorithm());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, catokeninfo.getEncryptionAlgorithm());
        assertEquals(SoftCryptoToken.class.getName(), catokeninfo.getClassPath());
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, catokeninfo.getKeySequenceFormat());
        
        cainfo = ca2.getCAInfo();
        catokeninfo = cainfo.getCATokenInfo();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, catokeninfo.getSignatureAlgorithm());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, catokeninfo.getEncryptionAlgorithm());
        assertEquals(SoftCryptoToken.class.getName(), catokeninfo.getClassPath());
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, catokeninfo.getKeySequenceFormat());

	}

	private static CVCCA createTestCA(String cadn) throws Exception {
		// Create catoken
		Properties prop = new Properties();
    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS); 
    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        // Set key generation property, since we have no old keys to generate the same sort
        prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, "512");
        CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), prop, null, 666);
        cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATESIGNKEYALIAS);
        cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATEDECKEYALIAS);
        
		CAToken catoken = new CAToken(cryptoToken);
		// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
		catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
		catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
		catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
		catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);

		CATokenInfo catokeninfo = catoken.getTokenInfo();
        // No extended services
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();

        CVCCAInfo cainfo = new CVCCAInfo(cadn, "TEST", CAConstants.CA_ACTIVE, new Date(), CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 3650, null, // Expiretime
                CAInfo.CATYPE_CVC, CAInfo.SELFSIGNED, (Collection<Certificate>) null, catokeninfo, "JUnit RSA CVC CA", -1, null, 
                24, // CRLPeriod
                0, // CRLIssueInterval
                10, // CRLOverlapTime
                10, // Delta CRL period
                new ArrayList<Integer>(), 
                true, // Finish User
                extendedcaservices, 
                new ArrayList<Integer>(), // Approvals Settings
                1, // Number of Req approvals
                true, // includeInHelathCheck
                true, // isDoEnforceUniquePublicKeys
                true, // isDoEnforceUniqueDistinguishedName
                false, // isDoEnforceUniqueSubjectDNSerialnumber
                true, // useCertReqHistory
                true, // useUserStorage
                true // useCertificateStorage
        );
        
        CVCCA cvcca = new CVCCA(cainfo);
        cvcca.setCAToken(catoken);
        // A CA certificate
        CAReferenceField caRef = new CAReferenceField("SE", "CAREF001", "00000");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "CAREF001", "00000");
        CVCertificate cv = CertificateGenerator.createTestCertificate(catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), caRef, holderRef, "SHA256WithRSA", AuthorizationRoleEnum.CVCA);
        CardVerifiableCertificate cvccacert = new CardVerifiableCertificate(cv);
        Certificate cacert = cvccacert;
		assertNotNull(cacert);
        Collection<Certificate> cachain = new ArrayList<Certificate>();
        cachain.add(cacert);
        cvcca.setCertificateChain(cachain);
        // Now our CA should be operational
        return cvcca;
	}


}
