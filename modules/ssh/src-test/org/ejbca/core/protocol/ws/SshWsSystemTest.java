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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
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
import org.ejbca.ssh.assertion.SshAssert;
import org.ejbca.ssh.certificate.SshEcCertificate;
import org.ejbca.ssh.keys.ec.SshEcKeyPair;
import org.ejbca.ssh.keys.ec.SshEcPublicKey;
import org.ejbca.ssh.keys.rsa.SshRsaPublicKey;
import org.ejbca.ssh.util.SshCaTestUtils;
import org.ejbca.ssh.util.SshTestUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test the WS methods that relate to SSH CAs
 *
 * @version $Id$
 */
public class SshWsSystemTest extends CommonEjbcaWs {

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SshWSTest"));

    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static List<File> fileHandles = new ArrayList<>();

    private static final String PASSWORD = "foo123";
    private static final String KEY_ID = "foo123";
    private static final String CUSTOM_EXTENSION_NAME = "customExtension";
    private static final byte[] CUSTOM_EXTENSION_VALUE = "customExtensionValue".getBytes();
    private static final String COMMENT = "A comment.";
    private static final String SOURCE_ADDRESS = "127.0.0.1";
    private static final List<String> PRINCIPALS = Arrays.asList("ejbca0", "ejbca1");

    private SshCa sshCa = null;
    private String caName = null;
    private String username = null;
    private String profileName = null;
    private int certificateProfileId = -1;

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

    @After
    public void tearDown() throws Exception {
        if(username != null) {
            try {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            } catch (CouldNotRemoveEndEntityException | NoSuchEndEntityException e) {
                //NOPMD
            }
            internalCertificateStoreSession.removeCertificatesByUsername(username);
        }
        if(profileName != null) {
            endEntityProfileSession.removeEndEntityProfile(internalAdmin, profileName);
            certificateProfileSession.removeCertificateProfile(internalAdmin, profileName);
        }
        if(sshCa != null) {
            CaTestUtils.removeCa(internalAdmin, sshCa.getCAInfo());
        }
    }

    /**
     * Test creates an SSH CA, then verifies that it can retrieve an EC public key correctly
     */
    @Test
    public void getSshCaPublicKeyAsEcP256() throws InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException, OperatorCreationException,
            CertificateException, CAExistsException, AuthorizationDeniedException, NoSuchSlotException, CADoesntExistsException_Exception,
            SshKeyException_Exception, InvalidKeySpecException, SshKeyException {
        final String caName = "testGetSshCaPublicKeyAsEcP256";
        sshCa = SshCaTestUtils.addSshCa(caName, SshEcPublicKey.SECP256R1, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        final String sshKey = new String(ejbcaraws.getSshCaPublicKey(caName));
        final String sshKeyBody = sshKey.split(" ")[1];
        final SshEcPublicKey sshEcPublicKey = new SshEcPublicKey(Base64.decode(sshKeyBody.getBytes()));
        assertEquals("CA key did not have the correct curve name.", SshEcPublicKey.NISTP256, sshEcPublicKey.getCurveName());
    }

    /**
     * Test creates an SSH CA, then verifies that it can retrieve an EC public key correctly
     */
    @Test
    public void getSshCaPublicKeyAsEcP384() throws InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException, OperatorCreationException,
            CertificateException, CAExistsException, AuthorizationDeniedException, NoSuchSlotException, CADoesntExistsException_Exception,
            SshKeyException_Exception, InvalidKeySpecException, SshKeyException {
        final String caName = "testGetSshCaPublicKeyAsEcP384";
        sshCa = SshCaTestUtils.addSshCa(caName, SshEcPublicKey.SECP384R1, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
        final String sshKey = new String(ejbcaraws.getSshCaPublicKey(caName));
        final String sshKeyBody = sshKey.split(" ")[1];
        final SshEcPublicKey sshEcPublicKey = new SshEcPublicKey(Base64.decode(sshKeyBody.getBytes()));
        assertEquals("CA key did not have the correct curve name.", SshEcPublicKey.NISTP384, sshEcPublicKey.getCurveName());
    }

    /**
     * Test creates an SSH CA, then verifies that it can retrieve an EC public key correctly
     */
    @Test
    public void getSshCaPublicKeyAsEcP521() throws InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException, OperatorCreationException,
            CertificateException, CAExistsException, AuthorizationDeniedException, NoSuchSlotException, CADoesntExistsException_Exception,
            SshKeyException_Exception, InvalidKeySpecException, SshKeyException {
        final String caName = "testGetSshCaPublicKeyAsEcP521";
        sshCa = SshCaTestUtils.addSshCa(caName, SshEcPublicKey.SECP521R1, AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA);
        final String sshKey = new String(ejbcaraws.getSshCaPublicKey(caName));
        final String sshKeyBody = sshKey.split(" ")[1];
        final SshEcPublicKey sshEcPublicKey = new SshEcPublicKey(Base64.decode(sshKeyBody.getBytes()));
        assertEquals("CA key did not have the correct curve name.", SshEcPublicKey.NISTP521, sshEcPublicKey.getCurveName());
    }

    /**
     * Test creates an SSH CA, then verifies that it can retrieve an RSA public key correctly
     */
    @Test
    public void getSshCaPublicKeyAsRsaSha1() throws InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException, OperatorCreationException,
            CertificateException, CAExistsException, AuthorizationDeniedException, NoSuchSlotException, CADoesntExistsException_Exception,
            SshKeyException_Exception, InvalidKeySpecException, SshKeyException {
        final String caName = "testGetSshCaPublicKeyAsRsaSha1";
        sshCa = SshCaTestUtils.addSshCa(caName, "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        String sshKey = new String(ejbcaraws.getSshCaPublicKey(caName));
        String sshKeyBody = sshKey.split(" ")[1];
        SshRsaPublicKey sshRsaPublicKey = new SshRsaPublicKey(Base64.decode(sshKeyBody.getBytes()));
        assertEquals("CA key did not have the correct encoding algorithm.", AlgorithmConstants.KEYALGORITHM_RSA,
                sshRsaPublicKey.getKeyAlgorithm());
    }

    /**
     * Tests enrolling and issuing an EC certificate over WS using a standard public key as input
     */
    @Test
    public void enrollAndIssueEcCertificate() throws AuthorizationDeniedException, InvalidKeyException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException,
            OperatorCreationException, CertificateException, CAExistsException, NoSuchSlotException, AuthorizationDeniedException_Exception,
            EjbcaException_Exception, EndEntityProfileValidationException_Exception, EndEntityProfileExistsException,
            CertificateProfileExistsException, NoSuchAlgorithmException, SignatureException, IOException, InvalidKeySpecException, SshKeyException {

        final UserDataVOWS userDataVOWS = getUserDataVOWS();
        final KeyPair keypair = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);

        final SshRequestMessageWs sshRequestMessageWs = new SshRequestMessageWs();
        sshRequestMessageWs.setAdditionalExtensions(getAdditionalExtensions());
        sshRequestMessageWs.setComment(COMMENT);
        sshRequestMessageWs.setCriticalOptions(getCriticalOptions(SOURCE_ADDRESS, "192.168.0.1"));
        sshRequestMessageWs.setKeyId(KEY_ID);
        sshRequestMessageWs.setPrincipals(PRINCIPALS);
        sshRequestMessageWs.setPublicKey(keypair.getPublic().getEncoded());
        sshCa = SshCaTestUtils.addSshCa(caName, SshEcPublicKey.SECP384R1, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
        createCertificateProfile();
        createEndEntityProfile();

        Date now = new Date(System.currentTimeMillis());
        String certificateBytes = new String(ejbcaraws.enrollAndIssueSshCertificate(userDataVOWS, sshRequestMessageWs));
        assertTrue("SSH certificate prefix was incorrect", certificateBytes.startsWith(SshEcCertificate.SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP256 + SshEcCertificate.SSH_EC_CERT_POSTFIX));
        assertTrue("Comment was not included", certificateBytes.endsWith(COMMENT));

        String ecCertificateBody = certificateBytes.split(" ")[1];
        byte[] decoded = Base64.decode(ecCertificateBody.getBytes());
        SshCertificateReader sshCertificateReader = new SshCertificateReader(decoded);

        assertEquals("Certificate algorithm was incorrect", "ecdsa-sha2-nistp256-cert-v01@openssh.com", sshCertificateReader.readString());
        readAndVerifyNonceAndCurveNameAndEcPointAndCertificate(sshCertificateReader, (ECPublicKey) keypair.getPublic());
        readAndVerifyPrincipals(sshCertificateReader);
        readAndVerifyValidity(sshCertificateReader, now);
        SshAssert.readAndVerifyCriticalOptions(sshCertificateReader, SOURCE_ADDRESS + ",192.168.0.1");
        readAndVerifyCertificateExtensions(sshCertificateReader);
        readAndVerifySignerAndSignature(sshCertificateReader);
        sshCertificateReader.close();
    }

    /**
     * Tests enrolling and issuing an EC certificate over WS using an SSH public key as input
     */
    @Test
    public void enrollAndIssueEcCertificateWithSshPublicKey() throws AuthorizationDeniedException, InvalidKeyException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidAlgorithmException,
            OperatorCreationException, CertificateException, CAExistsException, NoSuchSlotException, AuthorizationDeniedException_Exception,
            EjbcaException_Exception, EndEntityProfileValidationException_Exception, EndEntityProfileExistsException,
            CertificateProfileExistsException, NoSuchAlgorithmException, SignatureException, IOException, InvalidKeySpecException, SshKeyException {

        final UserDataVOWS userDataVOWS = getUserDataVOWS("WithSshPublicKey");
        final SshEcKeyPair sshEcKeyPair = new SshEcKeyPair(SshEcPublicKey.NISTP256);

        final SshRequestMessageWs sshRequestMessageWs = new SshRequestMessageWs();
        sshRequestMessageWs.setAdditionalExtensions(getAdditionalExtensions());
        sshRequestMessageWs.setComment(COMMENT);
        sshRequestMessageWs.setCriticalOptions(getCriticalOptions());
        sshRequestMessageWs.setKeyId(KEY_ID);
        sshRequestMessageWs.setPrincipals(PRINCIPALS);
        sshRequestMessageWs.setPublicKey(sshEcKeyPair.getPublicKey().encodeForExport("foo"));

        sshCa = SshCaTestUtils.addSshCa(caName, SshEcPublicKey.SECP384R1, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
        createCertificateProfile();
        createEndEntityProfile();

        Date now = new Date(System.currentTimeMillis());
        String certificateBytes = new String(ejbcaraws.enrollAndIssueSshCertificate(userDataVOWS, sshRequestMessageWs));
        assertTrue("SSH certificate prefix was incorrect", certificateBytes.startsWith(SshEcCertificate.SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP256 + SshEcCertificate.SSH_EC_CERT_POSTFIX));
        assertTrue("Comment was not included", certificateBytes.endsWith(COMMENT));

        String ecCertificateBody = certificateBytes.split(" ")[1];
        byte[] decoded = Base64.decode(ecCertificateBody.getBytes());
        SshCertificateReader sshCertificateReader = new SshCertificateReader(decoded);

        assertEquals("Certificate algorithm was incorrect", "ecdsa-sha2-nistp256-cert-v01@openssh.com", sshCertificateReader.readString());
        readAndVerifyNonceAndCurveNameAndEcPointAndCertificate(sshCertificateReader, (ECPublicKey) sshEcKeyPair.getPublicKey().getPublicKey());
        readAndVerifyPrincipals(sshCertificateReader);
        readAndVerifyValidity(sshCertificateReader, now);
        SshAssert.readAndVerifyCriticalOptions(sshCertificateReader, SOURCE_ADDRESS);
        readAndVerifyCertificateExtensions(sshCertificateReader);
        readAndVerifySignerAndSignature(sshCertificateReader);
        sshCertificateReader.close();
    }

    @Override
    public String getRoleName() {
        return "SshWsTest";
    }

    private Map<String, String> getCriticalOptions() {
        return getCriticalOptions(SOURCE_ADDRESS);
    }

    private Map<String, String> getCriticalOptions(final String... sourceAddress) {
        final Map<String, String> options = new HashMap<>();
        options.put(SshCertificate.CRITICAL_OPTION_SOURCE_ADDRESS, String.join(",", sourceAddress));
        return options;
    }

    private Map<String, byte[]> getAdditionalExtensions() {
        final Map<String, byte[]> extensions = new HashMap<>();
        extensions.put(CUSTOM_EXTENSION_NAME, CUSTOM_EXTENSION_VALUE);
        return extensions;
    }

    private UserDataVOWS getUserDataVOWS() {
        return getUserDataVOWS("");
    }

    private UserDataVOWS getUserDataVOWS(final String postfixName) {
        final UserDataVOWS userDataVOWS = new UserDataVOWS();
        username = "testEnrollAndIssueEcCertificate" + postfixName;
        userDataVOWS.setUsername(username);
        userDataVOWS.setPassword(PASSWORD);
        userDataVOWS.setClearPwd(false);
        userDataVOWS.setSubjectDN(null);
        caName = "testEnrollAndIssueEcCertificate" + postfixName;
        userDataVOWS.setCaName(caName);
        userDataVOWS.setEmail(null);
        userDataVOWS.setSubjectAltName(null);
        userDataVOWS.setStatus(EndEntityConstants.STATUS_NEW);
        userDataVOWS.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        profileName = "testEnrollAndIssueEcCertificate" + postfixName;
        userDataVOWS.setEndEntityProfileName(profileName);
        userDataVOWS.setCertificateProfileName(profileName);
        return userDataVOWS;
    }

    private void createCertificateProfile() throws CertificateProfileExistsException, AuthorizationDeniedException {
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateConstants.CERTTYPE_SSH);
        certificateProfile.setType(CertificateConstants.CERTTYPE_SSH);
        certificateProfile.setSshCertificateType(SshCertificateType.USER);
        certificateProfile.setSshExtensions(SshTestUtils.getAllSshExtensionsMap());
        certificateProfile.setAllowExternalSshExtensions(true);
        certificateProfile.setAvailableCAs(Collections.singletonList(sshCa.getCAId()));
        certificateProfileId = certificateProfileSession.addCertificateProfile(internalAdmin, profileName, certificateProfile);
    }

    private void createEndEntityProfile() throws EndEntityProfileExistsException, AuthorizationDeniedException {
        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.addField(SshEndEntityProfileFields.SSH_PRINCIPAL);
        endEntityProfile.addField(SshEndEntityProfileFields.SSH_PRINCIPAL);
        endEntityProfile.setSshSourceAddress(SOURCE_ADDRESS);
        endEntityProfile.setSshSourceAddressRequired(true);
        endEntityProfile.setRequired(DnComponents.COMMONNAME,0,false);
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Collections.singletonList(certificateProfileId));
        endEntityProfile.setDefaultCA(sshCa.getCAId());
        endEntityProfile.setAvailableCAs(Collections.singletonList(sshCa.getCAId()));
        endEntityProfileSession.addEndEntityProfile(internalAdmin, profileName, endEntityProfile);
    }

    private void readAndVerifyNonceAndCurveNameAndEcPointAndCertificate(
            final SshCertificateReader sshCertificateReader, final ECPublicKey ecPublicKey
    ) throws IOException, InvalidKeySpecException {
        byte[] nonce = sshCertificateReader.readByteArray();
        assertNotNull("Nonce was not read correctly", nonce);
        assertEquals("Nonce was not 32 bytes long.", 32, nonce.length);
        final String curveName = sshCertificateReader.readString();
        assertEquals("Curve name was not correct.", SshEcPublicKey.NISTP256, curveName);
        final byte[] pointBytes = sshCertificateReader.readByteArray();
        final ECParameterSpec ecParameterSpec = ECNamedCurveTable
                .getParameterSpec(AlgorithmTools.getEcKeySpecOidFromBcName(SshEcPublicKey.translateCurveName(curveName)));
        final EllipticCurve ellipticCurve = EC5Util.convertCurve(ecParameterSpec.getCurve(), ecParameterSpec.getSeed());
        final ECPoint ecPoint = KeyTools.decodeEcPoint(pointBytes, ellipticCurve);
        final ECPoint knownPoint = ecPublicKey.getW();
        assertEquals("EC Point was not correct", knownPoint, ecPoint);
        final BigInteger serialNumber = new BigInteger(Long.toUnsignedString(sshCertificateReader.readLong()));
        assertTrue("Certificate serial number negative", serialNumber.compareTo(new BigInteger("0")) > 0 );
        assertEquals("Certificate type was not correct", SshCertificateType.USER.getType(), sshCertificateReader.readInt());
        assertEquals("Key ID was not correct", KEY_ID, sshCertificateReader.readString());
    }

    private void readAndVerifyPrincipals(final SshCertificateReader sshCertificateReader) throws IOException {
        // Principals are enclosed in a byte structure of their own.
        byte[] principalsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader principalReader = new SshCertificateReader(principalsBytes);
        Set<String> certificatePrincipals = new HashSet<>();
        while (principalReader.available() > 0) {
            certificatePrincipals.add(principalReader.readString());
        }
        principalReader.close();
        assertTrue("Principal was not correct", certificatePrincipals.containsAll(PRINCIPALS));
    }

    private void readAndVerifyValidity(final SshCertificateReader sshCertificateReader, final Date now) throws IOException {
        Date validAfter = new Date(sshCertificateReader.readLong()*1000);
        assertTrue(validAfter.before(now));
        Date validBefore = new Date(sshCertificateReader.readLong()*1000);
        assertTrue(validBefore.after(now));
    }

    private void readAndVerifyCertificateExtensions(final SshCertificateReader sshCertificateReader) throws IOException {
        // Extensions are enclosed in a byte structure of their own
        final Map<String, byte[]> certificateExtensions = new HashMap<>();
        final byte[] extensionsBytes = sshCertificateReader.readByteArray();
        final SshCertificateReader extensionsReader = new SshCertificateReader(extensionsBytes);
        while (extensionsReader.available() > 0) {
            final String extensionName = extensionsReader.readString();
            final SshCertificateReader extensionValueReader = new SshCertificateReader(extensionsReader.readByteArray());
            byte[] extensionValue;
            if (extensionValueReader.available() > 0) {
                extensionValue = extensionValueReader.readByteArray();
            } else {
                extensionValue = new byte[0];
            }
            extensionValueReader.close();
            certificateExtensions.put(extensionName, extensionValue);
        }
        extensionsReader.close();
        final Map<String, byte[]> knownExtensions = SshTestUtils.getAllSshExtensionsMap();
        knownExtensions.put(CUSTOM_EXTENSION_NAME, CUSTOM_EXTENSION_VALUE);
        assertEquals("Wrong number of extensions were decoded.", knownExtensions.size(), certificateExtensions.size());
        assertArrayEquals("Custom extension was not decoded correctly.", certificateExtensions.get(CUSTOM_EXTENSION_NAME), CUSTOM_EXTENSION_VALUE);
        assertTrue("Reserved should not be used.", StringUtils.isEmpty(sshCertificateReader.readString()));
    }

    private void readAndVerifySignerAndSignature(final SshCertificateReader sshCertificateReader) throws IOException, InvalidKeySpecException, SshKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        final byte[] signKeyBytes = sshCertificateReader.readByteArray();
        final SshEcPublicKey signKey = new SshEcPublicKey(signKeyBytes);
        assertEquals("Signer Curve name was not correct.", SshEcPublicKey.NISTP384, signKey.getCurveName());
        final ECPoint signerEcPoint = ((ECPublicKey) signKey.getPublicKey()).getW();
        final ECPoint knownSignerEcPoint = ((ECPublicKey) sshCa.getCACertificate().getPublicKey()).getW();
        assertEquals("Signer EC point was incorrect", knownSignerEcPoint, signerEcPoint);
        // The signature also lives in its own structure
        final byte[] signatureBytes = sshCertificateReader.readByteArray();
        final SshCertificateReader signatureReader = new SshCertificateReader(signatureBytes);
        final String signaturePrefix = signatureReader.readString();
        assertEquals("Incorrect signature prefix", "ecdsa-sha2-nistp384", signaturePrefix);
        final byte[] strippedSignatureBytes = signatureReader.readByteArray();
        signatureReader.close();
        // The complete certificate body, minus the signature, i.e. that which was signed
        final byte[] data = new byte[sshCertificateReader.array().length - (signatureBytes.length + 4)];
        System.arraycopy(sshCertificateReader.array(), 0, data, 0, data.length);
        assertTrue("Certificate signature could not be verified",
                SshAssert.verifyEcSignature((ECPublicKey) signKey.getPublicKey(), strippedSignatureBytes, SshEcPublicKey.NISTP384, data));
    }
}
