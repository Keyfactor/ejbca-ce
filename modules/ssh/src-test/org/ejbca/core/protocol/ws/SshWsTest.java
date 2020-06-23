/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ws;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.ssh.SshCa;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.ssh.SshCertificate;
import org.cesecore.certificates.certificate.ssh.SshCertificateReader;
import org.cesecore.certificates.certificate.ssh.SshCertificateType;
import org.cesecore.certificates.certificate.ssh.SshEndEntityProfileFields;
import org.cesecore.certificates.certificate.ssh.SshExtension;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EndEntityProfileValidationException_Exception;
import org.ejbca.core.protocol.ws.client.gen.SshKeyException_Exception;
import org.ejbca.core.protocol.ws.client.gen.SshRequestMessageWs;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.ssh.certificate.SshEcCertificate;
import org.ejbca.ssh.keys.ec.SshEcKeyPair;
import org.ejbca.ssh.keys.ec.SshEcPublicKey;
import org.ejbca.ssh.keys.rsa.SshRsaPublicKey;
import org.ejbca.ssh.util.SshCaTestUtils;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test the WS methods that relate to SSH CAs
 * 
 * @version $Id$
 *
 */
public class SshWsTest extends CommonEjbcaWs {

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SshWSTest"));

    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static List<File> fileHandles = new ArrayList<>();

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        adminBeforeClass();
        fileHandles = setupAccessRights(WS_ADMIN_ROLENAME);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        cleanUpAdmins(WS_ADMIN_ROLENAME);
        for (File file : fileHandles) {
            FileTools.delete(file);
        }
    }

    @Before
    public void setUpAdmin() throws Exception {
        adminSetUpAdmin();
    }

    /**
     * Test creates an SSH CA, then verifies that it can retrieve an EC public key correctly
     */
    @Test
    public void testGetSshCaPublicKeyAsEcP256() throws InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException, OperatorCreationException,
            CertificateException, CAExistsException, AuthorizationDeniedException, NoSuchSlotException, CADoesntExistsException_Exception,
            SshKeyException_Exception, InvalidKeySpecException, SshKeyException {
        final String caName = "testGetSshCaPublicKeyAsEcP256";
        SshCa sshCa = SshCaTestUtils.addSshCa(caName, SshEcPublicKey.SECP256R1, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        try {
            String sshKey = new String(ejbcaraws.getSshCaPublicKey(caName));
            String sshKeyBody = sshKey.split(" ")[1];

            SshEcPublicKey sshEcPublicKey = new SshEcPublicKey(Base64.decode(sshKeyBody.getBytes()));
            assertEquals("CA key did not have the correct curve name.", SshEcPublicKey.NISTP256, sshEcPublicKey.getCurveName());
        } finally {
            CaTestUtils.removeCa(internalAdmin, sshCa.getCAInfo());
        }
    }

    /**
     * Test creates an SSH CA, then verifies that it can retrieve an EC public key correctly
     */
    @Test
    public void testGetSshCaPublicKeyAsEcP384() throws InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException, OperatorCreationException,
            CertificateException, CAExistsException, AuthorizationDeniedException, NoSuchSlotException, CADoesntExistsException_Exception,
            SshKeyException_Exception, InvalidKeySpecException, SshKeyException {
        final String caName = "testGetSshCaPublicKeyAsEcP384";
        SshCa sshCa = SshCaTestUtils.addSshCa(caName, SshEcPublicKey.SECP384R1, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
        try {
            String sshKey = new String(ejbcaraws.getSshCaPublicKey(caName));
            String sshKeyBody = sshKey.split(" ")[1];

            SshEcPublicKey sshEcPublicKey = new SshEcPublicKey(Base64.decode(sshKeyBody.getBytes()));
            assertEquals("CA key did not have the correct curve name.", SshEcPublicKey.NISTP384, sshEcPublicKey.getCurveName());
        } finally {
            CaTestUtils.removeCa(internalAdmin, sshCa.getCAInfo());
        }
    }

    /**
     * Test creates an SSH CA, then verifies that it can retrieve an EC public key correctly
     */
    @Test
    public void testGetSshCaPublicKeyAsEcP521() throws InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException, OperatorCreationException,
            CertificateException, CAExistsException, AuthorizationDeniedException, NoSuchSlotException, CADoesntExistsException_Exception,
            SshKeyException_Exception, InvalidKeySpecException, SshKeyException {
        final String caName = "testGetSshCaPublicKeyAsEcP521";
        SshCa sshCa = SshCaTestUtils.addSshCa(caName, SshEcPublicKey.SECP521R1, AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA);
        try {
            String sshKey = new String(ejbcaraws.getSshCaPublicKey(caName));
            String sshKeyBody = sshKey.split(" ")[1];

            SshEcPublicKey sshEcPublicKey = new SshEcPublicKey(Base64.decode(sshKeyBody.getBytes()));
            assertEquals("CA key did not have the correct curve name.", SshEcPublicKey.NISTP521, sshEcPublicKey.getCurveName());
        } finally {
            CaTestUtils.removeCa(internalAdmin, sshCa.getCAInfo());
        }
    }

    /**
     * Test creates an SSH CA, then verifies that it can retrieve an RSA public key correctly
     */
    @Test
    public void testGetSshCaPublicKeyAsRsaSha1() throws InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException, OperatorCreationException,
            CertificateException, CAExistsException, AuthorizationDeniedException, NoSuchSlotException, CADoesntExistsException_Exception,
            SshKeyException_Exception, InvalidKeySpecException, SshKeyException {
        final String caName = "testGetSshCaPublicKeyAsRsaSha1";
        SshCa sshCa = SshCaTestUtils.addSshCa(caName, "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        try {
            String sshKey = new String(ejbcaraws.getSshCaPublicKey(caName));
            String sshKeyBody = sshKey.split(" ")[1];

            SshRsaPublicKey sshRsaPublicKey = new SshRsaPublicKey(Base64.decode(sshKeyBody.getBytes()));
            assertEquals("CA key did not have the correct encoding algorithm.", AlgorithmConstants.KEYALGORITHM_RSA,
                    sshRsaPublicKey.getKeyAlgorithm());
        } finally {
            CaTestUtils.removeCa(internalAdmin, sshCa.getCAInfo());
        }
    }

    /**
     * Tests enrolling and issuing an EC certificate over WS using a standard public key as input 
     */
    @Test
    public void testEnrollAndIssueEcCertificate() throws AuthorizationDeniedException, InvalidKeyException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException,
            OperatorCreationException, CertificateException, CAExistsException, NoSuchSlotException, AuthorizationDeniedException_Exception,
            EjbcaException_Exception, EndEntityProfileValidationException_Exception, EndEntityProfileExistsException,
            CertificateProfileExistsException, NoSuchAlgorithmException, SignatureException, IOException, InvalidKeySpecException, SshKeyException {
        final String caName = "testEnrollAndIssueEcCertificate";
        final String username = "testEnrollAndIssueEcCertificate";
        final String password = "foo123";
        final String profileName = "testEnrollAndIssueEcCertificate";
        final String keyId = "foo123";
        final UserDataVOWS userDataVOWS = new UserDataVOWS();
        final String customExtensionName = "customExtension";
        final byte[] customExtensionValue = "customExtensionValue".getBytes();
        final String comment = "A comment.";
        userDataVOWS.setUsername(username);
        userDataVOWS.setPassword(password);
        userDataVOWS.setClearPwd(false);
        userDataVOWS.setSubjectDN(null);
        userDataVOWS.setCaName(caName);
        userDataVOWS.setEmail(null);
        userDataVOWS.setSubjectAltName(null);
        userDataVOWS.setStatus(EndEntityConstants.STATUS_NEW);
        userDataVOWS.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        userDataVOWS.setEndEntityProfileName(profileName);
        userDataVOWS.setCertificateProfileName(profileName);
        Map<String, String> criticalOptions = new HashMap<>();
        criticalOptions.put(SshCertificate.CRITICAL_OPTION_SOURCE_ADDRESS, "127.0.0.1");
        List<String> principals = Arrays.asList("ejbca0", "ejbca1");
        Map<String, byte[]> additionalExtensions = new HashMap<>();
        additionalExtensions.put(customExtensionName, customExtensionValue);
        
        KeyPair keypair = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        
        SshRequestMessageWs sshRequestMessageWs = new SshRequestMessageWs();
        sshRequestMessageWs.setAdditionalExtensions(additionalExtensions);
        sshRequestMessageWs.setComment(comment);
        sshRequestMessageWs.setCriticalOptions(criticalOptions);
        sshRequestMessageWs.setKeyId(keyId);
        sshRequestMessageWs.setPrincipals(principals);
        sshRequestMessageWs.setPublicKey(keypair.getPublic().getEncoded());
        String caCurve = SshEcPublicKey.SECP384R1;
        SshCa sshCa = SshCaTestUtils.addSshCa(caName, caCurve, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
        
        CertificateProfile certificateProfile = new CertificateProfile(CertificateConstants.CERTTYPE_SSH);
        certificateProfile.setType(CertificateConstants.CERTTYPE_SSH);
        certificateProfile.setSshCertificateType(SshCertificateType.USER);
        Map<String, byte[]> extensions = new HashMap<>();
        for(SshExtension sshExtension : SshExtension.values()) {
            extensions.put(sshExtension.getLabel(), sshExtension.getValue());
        }
        certificateProfile.setSshExtensions(extensions);
        certificateProfile.setAllowExternalSshExtensions(true);
        certificateProfile.setAvailableCAs(Arrays.asList(sshCa.getCAId()));
        int certificateProfileId = certificateProfileSession.addCertificateProfile(internalAdmin, profileName, certificateProfile);
        
        final String sshSourceAddress = "127.0.0.1";
        EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.addField(SshEndEntityProfileFields.SSH_PRINCIPAL);
        endEntityProfile.addField(SshEndEntityProfileFields.SSH_PRINCIPAL);
        endEntityProfile.setSshSourceAddress(sshSourceAddress);
        endEntityProfile.setSshSourceAddressRequired(true);
        endEntityProfile.setRequired(DnComponents.COMMONNAME,0,false);
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfile.setDefaultCA(sshCa.getCAId());
        endEntityProfile.setAvailableCAs(Arrays.asList(sshCa.getCAId()));
        endEntityProfileSession.addEndEntityProfile(internalAdmin, profileName, endEntityProfile);
        
        try {
            Date now = new Date(System.currentTimeMillis());
            String certificateBytes = new String(ejbcaraws.enrollAndIssueSshCertificate(userDataVOWS, sshRequestMessageWs));  
            assertTrue("SSH certificate prefix was incorrect", certificateBytes.startsWith(SshEcCertificate.SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP256 + SshEcCertificate.SSH_EC_CERT_POSTFIX));
            assertTrue("Comment was not included", certificateBytes.endsWith(comment));
            String ecCertificateBody = certificateBytes.split(" ")[1];
            
            byte[] decoded = Base64.decode(ecCertificateBody.getBytes());
            SshCertificateReader sshCertificateReader = new SshCertificateReader(decoded);
            assertEquals("Certificate algorithm was incorrect", "ecdsa-sha2-nistp256-cert-v01@openssh.com", sshCertificateReader.readString());
            byte[] nonce = sshCertificateReader.readByteArray();
            assertNotNull("Nonce was not read correctly", nonce);
            assertEquals("Nonce was not 32 bytes long.", 32, nonce.length);
            String curveName = sshCertificateReader.readString();
            assertEquals("Curve name was not correct.", SshEcPublicKey.NISTP256, curveName);
            byte[] pointBytes = sshCertificateReader.readByteArray();
            ECParameterSpec ecParameterSpec = ECNamedCurveTable
                    .getParameterSpec(AlgorithmTools.getEcKeySpecOidFromBcName(SshEcPublicKey.translateCurveName(curveName)));
            EllipticCurve ellipticCurve = EC5Util.convertCurve(ecParameterSpec.getCurve(), ecParameterSpec.getSeed());
            ECPoint ecPoint = KeyTools.decodeEcPoint(pointBytes, ellipticCurve);
            ECPoint knownPoint = ((ECPublicKey) keypair.getPublic()).getW();   
            assertEquals("EC Point was not correct", knownPoint, ecPoint);
            BigInteger serialNumber = new BigInteger(Long.toUnsignedString(sshCertificateReader.readLong()));
            assertTrue("Certificate serial number negative", serialNumber.compareTo(new BigInteger("0")) > 0 );
            assertEquals("Certificate type was not correct", SshCertificateType.USER.getType(), sshCertificateReader.readInt());
            assertEquals("Key ID was not correct", keyId, sshCertificateReader.readString());
            //Principals are enclosed in a byte structure of their own.
            byte[] principalsBytes = sshCertificateReader.readByteArray();
            SshCertificateReader principalReader = new SshCertificateReader(principalsBytes);
            Set<String> certificatePrincipals = new HashSet<>();
            while (principalReader.available() > 0) {
                certificatePrincipals.add(principalReader.readString());
            }
            principalReader.close();
            assertTrue("Principal was not correct", certificatePrincipals.containsAll(principals));
            Date validAfter = new Date(sshCertificateReader.readLong()*1000);
            assertTrue(validAfter.before(now));
            Date validBefore = new Date(sshCertificateReader.readLong()*1000);
            assertTrue(validBefore.after(now));
            //Critical options are enclosed in a byte structure of their own
            byte[] optionsBytes = sshCertificateReader.readByteArray();
            SshCertificateReader optionsReader = new SshCertificateReader(optionsBytes);
            Map<String, String> options = new HashMap<>();
            while (optionsReader.available() > 0) {
                String optionName = optionsReader.readString();
                //Value will be coded as a set of Strings
                byte[] optionValue = optionsReader.readByteArray();
                SshCertificateReader optionReader = new SshCertificateReader(optionValue);
                String optionList = "";
                while (optionReader.available() > 0) {
                    optionList += optionReader.readString();
                    if (optionReader.available() > 0) {
                        optionList += ",";
                    }
                }
                optionReader.close();
                options.put(optionName, optionList);
            }
            optionsReader.close();
            assertEquals("Incorrect critical options were read.", 1, options.size());
            assertTrue("Option was not found", options.containsKey("source-address"));
            assertEquals("Option value was incorrect", "127.0.0.1", options.get("source-address"));
            //Extensions are enclosed in a byte structure of their own
            Map<String, byte[]> certificateExtensions = new HashMap<>();
            byte[] extensionsBytes = sshCertificateReader.readByteArray();
            SshCertificateReader extensionsReader = new SshCertificateReader(extensionsBytes);
            while (extensionsReader.available() > 0) {
                String extensionName = extensionsReader.readString();
                SshCertificateReader extensionValueReader = new SshCertificateReader(extensionsReader.readByteArray());
                byte[] extensionValue;
                if (extensionValueReader.available() > 0) {
                    extensionValue = extensionValueReader.readByteArray();
                } else {
                    extensionValue = new byte[0];
                }
                extensions.put(extensionName, extensionValue);
                extensionValueReader.close();
                certificateExtensions.put(extensionName, extensionValue);
            }
            extensionsReader.close();
            Map<String, byte[]> knownExtensions = new HashMap<>();
            knownExtensions.putAll(extensions);
            knownExtensions.put(customExtensionName, customExtensionValue);
            assertEquals("Wrong number of extensions were decoded.", knownExtensions.size(), certificateExtensions.size());
            assertTrue("Custom extension was not decoded correctly.", Arrays.equals(certificateExtensions.get(customExtensionName), customExtensionValue));
            assertTrue("Reserved should not be used.", StringUtils.isEmpty(sshCertificateReader.readString()));

            byte[] signKeyBytes = sshCertificateReader.readByteArray();
            SshEcPublicKey signKey = new SshEcPublicKey(signKeyBytes);
            assertEquals("Signer Curve name was not correct.", SshEcPublicKey.NISTP384, signKey.getCurveName());
            ECPoint signerEcPoint = ((ECPublicKey) signKey.getPublicKey()).getW();
            ECPoint knownSignerEcPoint = ((ECPublicKey) sshCa.getCACertificate().getPublicKey()).getW();
            assertEquals("Signer EC point was incorrect", knownSignerEcPoint, signerEcPoint);
            //The signature also lives in its own structure
            byte[] signatureBytes = sshCertificateReader.readByteArray();
            SshCertificateReader signatureReader = new SshCertificateReader(signatureBytes);
            String signaturePrefix = signatureReader.readString();
            assertEquals("Incorrect signature prefix", "ecdsa-sha2-nistp384", signaturePrefix);
            byte[] strippedSignatureBytes = signatureReader.readByteArray();
            signatureReader.close();

            // The complete certificate body, minus the signature, i.e. that which was signed
            byte[] data = new byte[sshCertificateReader.array().length - (signatureBytes.length + 4)];
            System.arraycopy(sshCertificateReader.array(), 0, data, 0, data.length);
            assertTrue("Certificate signature could not be verified",
                    verifyEcSignature((ECPublicKey) signKey.getPublicKey(), strippedSignatureBytes, SshEcPublicKey.NISTP384, data));
            sshCertificateReader.close();        
        } finally {
            try {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            } catch (CouldNotRemoveEndEntityException | NoSuchEndEntityException e) {
                //NOPMD 
            }
            endEntityProfileSession.removeEndEntityProfile(internalAdmin, profileName);
            certificateProfileSession.removeCertificateProfile(internalAdmin, profileName);
            CaTestUtils.removeCa(internalAdmin, sshCa.getCAInfo());
            internalCertificateStoreSession.removeCertificatesByUsername(username);
 

        }
    }
    
    /**
     * Tests enrolling and issuing an EC certificate over WS using an SSH public key as input 
     */
    @Test
    public void testEnrollAndIssueEcCertificateWithSshPublicKey() throws AuthorizationDeniedException, InvalidKeyException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException,
            OperatorCreationException, CertificateException, CAExistsException, NoSuchSlotException, AuthorizationDeniedException_Exception,
            EjbcaException_Exception, EndEntityProfileValidationException_Exception, EndEntityProfileExistsException,
            CertificateProfileExistsException, NoSuchAlgorithmException, SignatureException, IOException, InvalidKeySpecException, SshKeyException {
        final String caName = "testEnrollAndIssueEcCertificateWithSshPublicKey";
        final String username = "testEnrollAndIssueEcCertificateWithSshPublicKey";
        final String password = "foo123";
        final String profileName = "testEnrollAndIssueEcCertificateWithSshPublicKey";
        final String keyId = "foo123";
        final UserDataVOWS userDataVOWS = new UserDataVOWS();
        final String customExtensionName = "customExtension";
        final byte[] customExtensionValue = "customExtensionValue".getBytes();
        final String comment = "A comment.";
        userDataVOWS.setUsername(username);
        userDataVOWS.setPassword(password);
        userDataVOWS.setClearPwd(false);
        userDataVOWS.setSubjectDN(null);
        userDataVOWS.setCaName(caName);
        userDataVOWS.setEmail(null);
        userDataVOWS.setSubjectAltName(null);
        userDataVOWS.setStatus(EndEntityConstants.STATUS_NEW);
        userDataVOWS.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        userDataVOWS.setEndEntityProfileName(profileName);
        userDataVOWS.setCertificateProfileName(profileName);
        Map<String, String> criticalOptions = new HashMap<>();
        criticalOptions.put(SshCertificate.CRITICAL_OPTION_SOURCE_ADDRESS, "127.0.0.1");
        List<String> principals = Arrays.asList("ejbca0", "ejbca1");
        Map<String, byte[]> additionalExtensions = new HashMap<>();
        additionalExtensions.put(customExtensionName, customExtensionValue);
        
        
        SshEcKeyPair sshEcKeyPair = new SshEcKeyPair(SshEcPublicKey.NISTP256);
        
        SshRequestMessageWs sshRequestMessageWs = new SshRequestMessageWs();
        sshRequestMessageWs.setAdditionalExtensions(additionalExtensions);
        sshRequestMessageWs.setComment(comment);
        sshRequestMessageWs.setCriticalOptions(criticalOptions);
        sshRequestMessageWs.setKeyId(keyId);
        sshRequestMessageWs.setPrincipals(principals);
        sshRequestMessageWs.setPublicKey(sshEcKeyPair.getPublicKey().encodeForExport("foo"));
        
        SshCa sshCa = SshCaTestUtils.addSshCa(caName, SshEcPublicKey.SECP384R1, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
        
        CertificateProfile certificateProfile = new CertificateProfile(CertificateConstants.CERTTYPE_SSH);
        certificateProfile.setType(CertificateConstants.CERTTYPE_SSH);
        certificateProfile.setSshCertificateType(SshCertificateType.USER);
        Map<String, byte[]> extensions = new HashMap<>();
        for(SshExtension sshExtension : SshExtension.values()) {
            extensions.put(sshExtension.getLabel(), sshExtension.getValue());
        }
        certificateProfile.setSshExtensions(extensions);
        certificateProfile.setAllowExternalSshExtensions(true);
        certificateProfile.setAvailableCAs(Arrays.asList(sshCa.getCAId()));
        int certificateProfileId = certificateProfileSession.addCertificateProfile(internalAdmin, profileName, certificateProfile);
        
        final String sshSourceAddress = "127.0.0.1";
        EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.addField(SshEndEntityProfileFields.SSH_PRINCIPAL);
        endEntityProfile.addField(SshEndEntityProfileFields.SSH_PRINCIPAL);
        endEntityProfile.setSshSourceAddress(sshSourceAddress);
        endEntityProfile.setSshSourceAddressRequired(true);
        endEntityProfile.setRequired(DnComponents.COMMONNAME,0,false);
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfile.setDefaultCA(sshCa.getCAId());
        endEntityProfile.setAvailableCAs(Arrays.asList(sshCa.getCAId()));
        endEntityProfileSession.addEndEntityProfile(internalAdmin, profileName, endEntityProfile);
        
        try {
            Date now = new Date(System.currentTimeMillis());
            String certificateBytes = new String(ejbcaraws.enrollAndIssueSshCertificate(userDataVOWS, sshRequestMessageWs));  
            assertTrue("SSH certificate prefix was incorrect", certificateBytes.startsWith(SshEcCertificate.SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP256 + SshEcCertificate.SSH_EC_CERT_POSTFIX));
            assertTrue("Comment was not included", certificateBytes.endsWith(comment));
            String ecCertificateBody = certificateBytes.split(" ")[1];          
            byte[] decoded = Base64.decode(ecCertificateBody.getBytes());
            SshCertificateReader sshCertificateReader = new SshCertificateReader(decoded);
            assertEquals("Certificate algorithm was incorrect", "ecdsa-sha2-nistp256-cert-v01@openssh.com", sshCertificateReader.readString());
            byte[] nonce = sshCertificateReader.readByteArray();
            assertNotNull("Nonce was not read correctly", nonce);
            assertEquals("Nonce was not 32 bytes long.", 32, nonce.length);
            String curveName = sshCertificateReader.readString();
            assertEquals("Curve name was not correct.", SshEcPublicKey.NISTP256, curveName);
            byte[] pointBytes = sshCertificateReader.readByteArray();
            ECParameterSpec ecParameterSpec = ECNamedCurveTable
                    .getParameterSpec(AlgorithmTools.getEcKeySpecOidFromBcName(SshEcPublicKey.translateCurveName(curveName)));
            EllipticCurve ellipticCurve = EC5Util.convertCurve(ecParameterSpec.getCurve(), ecParameterSpec.getSeed());
            ECPoint ecPoint = KeyTools.decodeEcPoint(pointBytes, ellipticCurve);
            ECPoint knownPoint = ((ECPublicKey) sshEcKeyPair.getPublicKey().getPublicKey()).getW();   
            assertEquals("EC Point was not correct", knownPoint, ecPoint);
            BigInteger serialNumber = new BigInteger(Long.toUnsignedString(sshCertificateReader.readLong()));
            assertTrue("Certificate serial number negative", serialNumber.compareTo(new BigInteger("0")) > 0 );
            assertEquals("Certificate type was not correct", SshCertificateType.USER.getType(), sshCertificateReader.readInt());
            assertEquals("Key ID was not correct", keyId, sshCertificateReader.readString());
            //Principals are enclosed in a byte structure of their own.
            byte[] principalsBytes = sshCertificateReader.readByteArray();
            SshCertificateReader principalReader = new SshCertificateReader(principalsBytes);
            Set<String> certificatePrincipals = new HashSet<>();
            while (principalReader.available() > 0) {
                certificatePrincipals.add(principalReader.readString());
            }
            principalReader.close();
            assertTrue("Principal was not correct", certificatePrincipals.containsAll(principals));
            Date validAfter = new Date(sshCertificateReader.readLong()*1000);
            assertTrue(validAfter.before(now));
            Date validBefore = new Date(sshCertificateReader.readLong()*1000);
            assertTrue(validBefore.after(now));            
            //Critical options are enclosed in a byte structure of their own
            byte[] optionsBytes = sshCertificateReader.readByteArray();
            SshCertificateReader optionsReader = new SshCertificateReader(optionsBytes);
            Map<String, String> options = new HashMap<>();
            while (optionsReader.available() > 0) {
                String optionName = optionsReader.readString();
                //Value will be coded as a set of Strings
                byte[] optionValue = optionsReader.readByteArray();
                SshCertificateReader optionReader = new SshCertificateReader(optionValue);
                String optionList = "";
                while (optionReader.available() > 0) {
                    optionList += optionReader.readString();
                    if (optionReader.available() > 0) {
                        optionList += ",";
                    }
                }
                optionReader.close();
                options.put(optionName, optionList);
            }
            optionsReader.close();
            assertEquals("Incorrect critical options were read.", 1, options.size());
            assertTrue("Option was not found", options.containsKey("source-address"));
            assertEquals("Option value was incorrect", "127.0.0.1", options.get("source-address"));
            //Extensions are enclosed in a byte structure of their own
            Map<String, byte[]> certificateExtensions = new HashMap<>();
            byte[] extensionsBytes = sshCertificateReader.readByteArray();
            SshCertificateReader extensionsReader = new SshCertificateReader(extensionsBytes);
            while (extensionsReader.available() > 0) {
                String extensionName = extensionsReader.readString();
                SshCertificateReader extensionValueReader = new SshCertificateReader(extensionsReader.readByteArray());
                byte[] extensionValue;
                if (extensionValueReader.available() > 0) {
                    extensionValue = extensionValueReader.readByteArray();
                } else {
                    extensionValue = new byte[0];
                }
                extensions.put(extensionName, extensionValue);
                extensionValueReader.close();
                certificateExtensions.put(extensionName, extensionValue);
            }
            extensionsReader.close();
            Map<String, byte[]> knownExtensions = new HashMap<>();
            knownExtensions.putAll(extensions);
            knownExtensions.put(customExtensionName, customExtensionValue);
            assertEquals("Wrong number of extensions were decoded.", knownExtensions.size(), certificateExtensions.size());
            assertTrue("Custom extension was not decoded correctly.", Arrays.equals(certificateExtensions.get(customExtensionName), customExtensionValue));
            assertTrue("Reserved should not be used.", StringUtils.isEmpty(sshCertificateReader.readString()));

            byte[] signKeyBytes = sshCertificateReader.readByteArray();
            SshEcPublicKey signKey = new SshEcPublicKey(signKeyBytes);
            assertEquals("Signer Curve name was not correct.", SshEcPublicKey.NISTP384, signKey.getCurveName());
            ECPoint signerEcPoint = ((ECPublicKey) signKey.getPublicKey()).getW();
            ECPoint knownSignerEcPoint = ((ECPublicKey) sshCa.getCACertificate().getPublicKey()).getW();
            assertEquals("Signer EC point was incorrect", knownSignerEcPoint, signerEcPoint);
            //The signature also lives in its own structure
            byte[] signatureBytes = sshCertificateReader.readByteArray();
            SshCertificateReader signatureReader = new SshCertificateReader(signatureBytes);
            String signaturePrefix = signatureReader.readString();
            assertEquals("Incorrect signature prefix", "ecdsa-sha2-nistp384", signaturePrefix);
            byte[] strippedSignatureBytes = signatureReader.readByteArray();
            signatureReader.close();

            // The complete certificate body, minus the signature, i.e. that which was signed
            byte[] data = new byte[sshCertificateReader.array().length - (signatureBytes.length + 4)];
            System.arraycopy(sshCertificateReader.array(), 0, data, 0, data.length);
            assertTrue("Certificate signature could not be verified",
                    verifyEcSignature((ECPublicKey) signKey.getPublicKey(), strippedSignatureBytes, SshEcPublicKey.NISTP384, data));
            sshCertificateReader.close();        
        } finally {
            try {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            } catch (CouldNotRemoveEndEntityException | NoSuchEndEntityException e) {
                //NOPMD 
            }
            endEntityProfileSession.removeEndEntityProfile(internalAdmin, profileName);
            certificateProfileSession.removeCertificateProfile(internalAdmin, profileName);
            CaTestUtils.removeCa(internalAdmin, sshCa.getCAInfo());
            internalCertificateStoreSession.removeCertificatesByUsername(username);
 

        }
    }
    
    private boolean verifyEcSignature(ECPublicKey publicKey, byte[] signatureBytes, String signatureAlgorithm, byte[] data)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException {
        Signature signature;
        switch (signatureAlgorithm) {
        case SshEcPublicKey.NISTP521:
            signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA);
            break;
        case SshEcPublicKey.NISTP384:
            signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
            break;
        default:
            signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
            break;
        }
                       
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DERSequenceGenerator seq = new DERSequenceGenerator(byteArrayOutputStream);
        SshCertificateReader sshCertificateReader = new SshCertificateReader(signatureBytes);
        seq.addObject(new ASN1Integer(sshCertificateReader.readBigInteger()));
        seq.addObject(new ASN1Integer(sshCertificateReader.readBigInteger()));
        sshCertificateReader.close();
        seq.close();
        byte[] encoded = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(encoded);
    }

    @Override
    public String getRoleName() {
        return "SshWsTest";
    }

}
