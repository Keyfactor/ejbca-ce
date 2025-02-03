/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.ra;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.CertificateSignatureException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyStoreCipher;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Test generating tokens
 * @version $Id$
 *
 */
public class GenerateTokenSystemTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(GenerateTokenSystemTest.class);

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("GenerateTokenSystemTest"));
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    private static final EndEntityAccessSessionRemote eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final KeyStoreCreateSessionRemote keyStoreCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyStoreCreateSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    private static final String TESTGENERATETOKENCA = "GENERATETOKENTEST_CA";
    private static final String GENERATETOKENTEST_EEP = "GENERATETOKENTEST_EEP";
    private static final String GENERATETOKENTEST_CERTIFICATE_PROFILE = "GENERATETOKENTEST_CERTIFICATE_PROFILE";
    private static final String GENERATETOKENTEST_USERNAME = "GENERATETOKENTEST_USERNAME";
    private  int certProfileId = 0;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();

    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();


        createTestCA(TESTGENERATETOKENCA);
        
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setUseAlternativeSignature(true);
        profile.setAlternativeAvailableKeyAlgorithms(new String[]{AlgorithmConstants.SIGALG_FALCON1024, AlgorithmConstants.SIGALG_FALCON512});
        profile.setAlternativeSignatureAlgorithm(AlgorithmConstants.SIGALG_FALCON1024);
        certProfileId = certificateProfileSession.addCertificateProfile(internalAdmin, GENERATETOKENTEST_CERTIFICATE_PROFILE, profile);
        
        final int caId1 = caSession.getCAInfo(internalAdmin, TESTGENERATETOKENCA).getCAId();
        final Collection<Integer> availcas = new ArrayList<Integer>();
        availcas.add(caId1);
        final EndEntityProfile eeprofile = new EndEntityProfile();
        eeprofile.setAvailableCAs(availcas);
        eeprofile.setAvailableCertificateProfileIds(Collections.singleton(certProfileId));
        endEntityProfileSession.addEndEntityProfile(internalAdmin, GENERATETOKENTEST_EEP, eeprofile);

    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        
        certificateProfileSession.removeCertificateProfile(internalAdmin, GENERATETOKENTEST_CERTIFICATE_PROFILE);
        endEntityProfileSession.removeEndEntityProfile(internalAdmin, GENERATETOKENTEST_EEP);
        removeOldCa(TESTGENERATETOKENCA);
    }

    /**
     * Tests if token algorithm specified in endEntityInformation is enforced. If end entity is approved its algorithm
     * is approved as well. So if there is specified algorithm inside endEntityInformation.extendedInformation that one
     * should be enforced. 
     */
    @Test
    public void testEnforcingAlgorithmFromEndEntityInformation() throws Exception {
        log.trace(">testEnforcingAlgorithmFromEndEntityInformation");
        try {
            final int caId = caSession.getCAInfo(internalAdmin, TESTGENERATETOKENCA).getCAId();
            final int eeProfileId = endEntityProfileSession.getEndEntityProfileId(GENERATETOKENTEST_EEP);

            EndEntityInformation eeinfo = new EndEntityInformation(GENERATETOKENTEST_USERNAME, "CN=GENERATETOKENTEST" + new Random().nextLong(), caId, "", null,
                    EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(), eeProfileId,
                    certProfileId, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
            eeinfo.setPassword("foo123");
            if (eeinfo.getExtendedInformation() == null) {
                eeinfo.setExtendedInformation(new ExtendedInformation());
            }
            //Setting up algorithm specification ECDSA_secp256r1 that is going to be enforced
            eeinfo.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_ECDSA);
            eeinfo.getExtendedInformation().setKeyStoreAlgorithmSubType("prime256v1");

            endEntityManagementSession.addUser(internalAdmin, eeinfo, false);
            endEntityManagementSession.setPassword(internalAdmin, GENERATETOKENTEST_USERNAME, "foo123");
            eeinfo = eeAccessSession.findUser(internalAdmin, GENERATETOKENTEST_USERNAME);
            assertNotNull("Could not find test user", GENERATETOKENTEST_USERNAME);
            eeinfo.setPassword("foo123");

            //Providing separately algorithm RSA_1024 that is going to be overridden with ECDSA_secp256r1
            final byte[] keyStore = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, GENERATETOKENTEST_USERNAME, "foo123", caId, "1024",
                    AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_P12, false, true, false, eeProfileId);
            KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            ks.load(new ByteArrayInputStream(keyStore), eeinfo.getPassword().toCharArray());
            Certificate cert = null;
            Enumeration<String> enumer = ks.aliases();
            while (enumer.hasMoreElements()) {
                String alias = enumer.nextElement();
                //The returned keystore will contain trusted certificate entry as well. We want to check key entry only.
                if(ks.isKeyEntry(alias)) {
                    cert = ks.getCertificate(alias);
                    assertNotNull("Unknown alias " + alias, cert); 
                }
            }
            PublicKey publicKey = cert.getPublicKey();
            assertEquals(AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(publicKey));
            assertEquals("prime256v1", AlgorithmTools.getKeySpecification(publicKey));
            
        } finally {
            if (endEntityManagementSession.existsUser(GENERATETOKENTEST_USERNAME)) {
                endEntityManagementSession.deleteUser(internalAdmin, GENERATETOKENTEST_USERNAME);
            }
            log.trace("<testEnforcingAlgorithmFromEndEntityInformation");
        }
    }
    
    /**
     * Verifies that the cipher is correctly read from the end entity profile
     */
    @Test
    public void testP12Cipher() throws EndEntityProfileExistsException, AuthorizationDeniedException, EndEntityExistsException,
            CADoesntExistsException, IllegalNameException, CustomFieldException, ApprovalException, CertificateSerialNumberException,
            EndEntityProfileValidationException, WaitingForApprovalException, NoSuchEndEntityException, CouldNotRemoveEndEntityException,
            KeyStoreException, InvalidAlgorithmParameterException, IllegalKeyException, CertificateCreateException, CertificateRevokeException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException, CertificateException, NoSuchAlgorithmException,
            InvalidKeySpecException, CertificateSignatureException, IOException, NoSuchProviderException, NoSuchPaddingException, EndEntityProfileNotFoundException {
        final String profileName = "testP12Cipher";
        final String username = "testP12Cipher";
        final EndEntityProfile eeprofile = new EndEntityProfile();
        eeprofile.setAvailableCertificateProfileIds(Collections.singleton(certProfileId));
        eeprofile.setP12Cipher(KeyStoreCipher.PKCS12_3DES_3DES);
        eeprofile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));
        int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(internalAdmin, profileName, eeprofile);
        final int caId = caSession.getCAInfo(internalAdmin, TESTGENERATETOKENCA).getCAId();

        try  {
            EndEntityInformation eeinfo = new EndEntityInformation(username, "CN="+username, caId, "", null,
                    EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(), endEntityProfileId,
                    certProfileId, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
            eeinfo.setPassword("foo123");
            endEntityManagementSession.addUser(internalAdmin, eeinfo, false);
            endEntityManagementSession.setPassword(internalAdmin, username, "foo123");
            eeinfo = eeAccessSession.findUser(internalAdmin, username);
            eeinfo.setPassword("foo123");
            final byte[] tripleDesKeyStore = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, username, "foo123", caId, "1024",
                    AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_P12, false, true, false, endEntityProfileId);
            assertEquals("PKCS#12 was not encrypted with 3DES", PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC.getId(), getEncryptionAlgorithmFromKeystore(tripleDesKeyStore));
            //Modify profile to take AES instead
            eeprofile.setP12Cipher(KeyStoreCipher.PKCS12_AES256_AES128);
            endEntityProfileSession.changeEndEntityProfile(internalAdmin, profileName, eeprofile);
            endEntityManagementSession.setUserStatus(internalAdmin, username, EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.setPassword(internalAdmin, username, "foo123");
            final byte[] aesKeystore = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, username, "foo123", caId, "1024",
                    AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_P12, false, true, false, endEntityProfileId);
            assertEquals("PKCS#12 was not encrypted with AES",  NISTObjectIdentifiers.id_aes128_CBC.getId(), getEncryptionAlgorithmFromKeystore(aesKeystore));
            
        } finally {
            if (endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            }           
            endEntityProfileSession.removeEndEntityProfile(internalAdmin, profileName);
        }
    }
    
    private String getEncryptionAlgorithmFromKeystore(byte[] keystoreBytes) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        BufferedInputStream bufIn = new BufferedInputStream(new ByteArrayInputStream(keystoreBytes));
        ASN1InputStream bIn = new ASN1InputStream(bufIn);
        Pfx bag = Pfx.getInstance(bIn.readObject());
        bIn.close();
        ASN1OctetString content = ASN1OctetString.getInstance(bag.getAuthSafe().getContent());
        final ASN1ObjectIdentifier encryptedData = new ASN1ObjectIdentifier("1.2.840.113549.1.7.6").intern();       
        for (ContentInfo contentInfo : AuthenticatedSafe.getInstance(content.getOctets()).getContentInfo()) {
            //Ignore other content types
            if (contentInfo.getContentType().equals(encryptedData)) {               
                ASN1ObjectIdentifier pbeAlgorithm = EncryptedData.getInstance(contentInfo.getContent()).getEncryptionAlgorithm().getAlgorithm();
                if (pbeAlgorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
                    //Using 3DES
                    final JcaJceHelper helper = new BCJcaJceHelper();
                    Cipher cipher = helper.createCipher(pbeAlgorithm.getId());
                    return cipher.getAlgorithm();
                } else if(pbeAlgorithm.equals(PKCSObjectIdentifiers.id_PBES2)) {
                    //Using AES
                    PBES2Parameters pbes2Parameters = PBES2Parameters.getInstance(EncryptedData.getInstance(contentInfo.getContent()).getEncryptionAlgorithm().getParameters());
                    return pbes2Parameters.getEncryptionScheme().getAlgorithm().getId();
                } else {
                    throw new IllegalStateException("Unknown PBE algorithm.");
                }               
            }
        }
        throw new IllegalStateException("No encrypted bag was found.");       
    }
    
    @Ignore
    public void testAlternateAlgorithmFromEndEntityInformation() throws Exception {
        log.trace(">testAlternateAlgorithmFromEndEntityInformation");
        try {
            final int caId = caSession.getCAInfo(internalAdmin, TESTGENERATETOKENCA).getCAId();
            final int eeProfileId = endEntityProfileSession.getEndEntityProfileId(GENERATETOKENTEST_EEP);
         
            
            EndEntityInformation eeinfo = new EndEntityInformation(GENERATETOKENTEST_USERNAME, "CN=GENERATETOKENTEST" + new Random().nextLong(), caId, "", null,
                    EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(), eeProfileId,
                    certProfileId, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
            eeinfo.setPassword("foo123");
            if (eeinfo.getExtendedInformation() == null) {
                eeinfo.setExtendedInformation(new ExtendedInformation());
            }
            //Setting up algorithm specification ECDSA_secp256r1 that is going to be enforced
            eeinfo.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_ECDSA);
            eeinfo.getExtendedInformation().setKeyStoreAlgorithmSubType("prime256v1");
            eeinfo.getExtendedInformation().setKeyStoreAlternativeKeyAlgorithm(AlgorithmConstants.SIGALG_FALCON1024);
            eeinfo.getExtendedInformation().setKeyStoreAlternativeKeySpecification(AlgorithmConstants.KEYALGORITHM_FALCON1024);
            endEntityManagementSession.addUser(internalAdmin, eeinfo, false);
            endEntityManagementSession.setPassword(internalAdmin, GENERATETOKENTEST_USERNAME, "foo123");
            eeinfo = eeAccessSession.findUser(internalAdmin, GENERATETOKENTEST_USERNAME);
            assertNotNull("Could not find test user", GENERATETOKENTEST_USERNAME);
            eeinfo.setPassword("foo123");
            //Providing separately algorithm RSA_1024 that is going to be overridden with ECDSA_secp256r1
            final byte[] keyStore = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, GENERATETOKENTEST_USERNAME, "foo123", caId, "1024",
                    AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.KEYALGORITHM_FALCON1024, AlgorithmConstants.KEYALGORITHM_FALCON1024, SecConst.TOKEN_SOFT_P12, false, true, false, eeProfileId);
            KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            ks.load(new ByteArrayInputStream(keyStore), eeinfo.getPassword().toCharArray());
            assertEquals("Re-loaded keystore was not created with the correct cipher.", KeyStoreCipher.PKCS12_AES256_AES128.getLabel(), ks.getType());
            Certificate cert = null;
            Enumeration<String> enumer = ks.aliases();
            while (enumer.hasMoreElements()) {
                String alias = enumer.nextElement();
                //The returned keystore will contain trusted certificate entry as well. We want to check key entry only.
                if(ks.isKeyEntry(alias)) {
                    cert = ks.getCertificate(alias);
                    assertNotNull("Unknown alias " + alias, cert); 
                }
            }
            PublicKey publicKey = cert.getPublicKey();
            final ASN1Primitive altPublicKeyAsn1 = CertTools.getExtensionValue((X509Certificate)cert, Extension.subjectAltPublicKeyInfo.getId());
            byte[] altASN1PrimitiveByte =  altPublicKeyAsn1.toASN1Primitive().getEncoded();
            PublicKey altPublicKey = KeyTools.getPublicKeyFromBytes(altASN1PrimitiveByte);
            assertEquals(AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(publicKey));
            assertEquals("prime256v1", AlgorithmTools.getKeySpecification(publicKey));
            assertEquals(AlgorithmConstants.SIGALG_FALCON1024, AlgorithmTools.getKeyAlgorithm(altPublicKey));
            assertEquals(AlgorithmConstants.KEYALGORITHM_FALCON1024, AlgorithmTools.getKeySpecification(altPublicKey));
            
        } finally {
            if (endEntityManagementSession.existsUser(GENERATETOKENTEST_USERNAME)) {
                endEntityManagementSession.deleteUser(internalAdmin, GENERATETOKENTEST_USERNAME);
            }
            log.trace("<testAlternateAlgorithmFromEndEntityInformation");
        }
    }
 
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
}

