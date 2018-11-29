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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfigurationHolder;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * This will test will check performing key updates over CMP. 
 * 
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CrmfKeyUpdateTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CrmfKeyUpdateTest.class);
        
    private static final String RENEWAL_USERNAME = "certRenewalUser";
    private static final X500Name RENEWAL_USER_DN = new X500Name("CN="+RENEWAL_USERNAME+",O=PrimeKey Solutions AB,C=SE");
    private static final String TEST_CA_NAME = "TestCA";
    private static final String TEST_CA_DN = "CN="+TEST_CA_NAME;
    private final byte[] nonce = CmpMessageHelper.createSenderNonce();
    private final byte[] transid = CmpMessageHelper.createSenderNonce();
    private final int caid;
    private final X509Certificate cacert;
    private final CA testx509ca;
    private final CmpConfiguration cmpConfiguration;
    private final String cmpAlias = "CrmfKeyUpdateTestCmpConfigAlias";

    
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    public CrmfKeyUpdateTest() throws Exception {
        this.cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);        
        this.testx509ca = CaTestUtils.createTestX509CA(TEST_CA_DN, null, false,
                X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        this.caid = this.testx509ca.getCAId();
        this.cacert = (X509Certificate) this.testx509ca.getCACertificate();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        caSession.addCA(ADMIN, testx509ca);
        // Initialize config in here
        EjbcaConfigurationHolder.instance();    
        this.cmpConfiguration.addAlias(this.cmpAlias);
        this.cmpConfiguration.setRAEEProfile(this.cmpAlias, String.valueOf(EndEntityConstants.EMPTY_END_ENTITY_PROFILE));
        this.cmpConfiguration.setRACertProfile(this.cmpAlias, "ENDUSER");
        this.cmpConfiguration.setRACAName(this.cmpAlias, TEST_CA_NAME);
        this.cmpConfiguration.setCMPDefaultCA(this.cmpAlias, TEST_CA_NAME);
        this.cmpConfiguration.setRAMode(this.cmpAlias, false);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, "RegTokenPwd;HMAC");
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, "-;-");
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        CryptoTokenTestUtils.removeCryptoToken(null, this.testx509ca.getCAToken().getCryptoTokenId());
        this.caSession.removeCA(ADMIN, this.caid);      
        try {
            this.endEntityManagementSession.revokeAndDeleteUser(ADMIN, RENEWAL_USERNAME, ReasonFlags.unused);
            this.endEntityManagementSession.revokeAndDeleteUser(ADMIN, "fakeuser", ReasonFlags.unused);

        } catch(Exception e){/* do nothing */}   
        this.cmpConfiguration.removeAlias(this.cmpAlias);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        internalCertificateStoreSession.removeCertificatesByUsername(RENEWAL_USERNAME);
    }

    
    /**
     * A "Happy Path" test. Sends a KeyUpdateRequest and receives a new certificate.
     * 
     * - Pre-configuration: Sets the operational mode to client mode (cmp.raoperationalmode=normal)
     * - Pre-configuration: Sets cmp.allowautomaticrenewal to 'true' and tests that the resetting of configuration has worked.
     * - Pre-configuration: Sets cmp.allowupdatewithsamekey to 'true'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Sends the request using HTTP and receives a response.
     * - Examines the response:
     *      - Checks that the response is not empty or null
     *      - Checks that the protection algorithm is sha1WithRSAEncryption
     *      - Checks that the signer is the expected CA
     *      - Verifies the response signature
     *      - Checks that the response's senderNonce is 16 bytes long
     *      - Checks that the request's senderNonce is the same as the response's recipientNonce
     *      - Checks that the request and the response has the same transactionID
     *      - Obtains the certificate from the response
     *      - Checks that the obtained certificate has the right subjectDN and issuerDN
     * 
     * @throws Exception
     */
    @Test
    public void test01KeyUpdateRequestOK() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test01KeyUpdateRequestOK");
        }
        
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.cmpConfiguration.setKurAllowSameKey(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        //--------------- create the user and issue his first certificate -----------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate;
        try {
            certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        } catch (NoSuchEndEntityException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (CADoesntExistsException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (EjbcaException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (CesecoreException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        }
        assertNotNull("Failed to create a test certificate", certificate);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, null, null, pAlg, new DEROctetString(this.nonce));
        assertNotNull("Failed to generate a CMP renewal request", req);
        CertReqMessages kur = (CertReqMessages) req.getBody().getContent();
        int reqId = kur.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        CMPCertificate[] extraCert = getCMPCert(certificate);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);     
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkKurCertRepMessage(RENEWAL_USER_DN, this.cacert, resp, reqId);
        assertNotNull("Failed to renew the certificate", cert);
        assertTrue("The new certificate's keys are incorrect.", cert.getPublicKey().equals(keys.getPublic()));
        if(log.isTraceEnabled()) {
            log.trace("<test01KeyUpdateRequestOK");
        }
    }

    /**
     * Sends a KeyUpdateRequest for a certificate that belongs to an end entity whose status is not NEW and the configurations is 
     * NOT to allow changing the end entity status automatically. A CMP error message is expected and no certificate renewal.
     * 
     * - Pre-configuration: Sets the operational mode to client mode (cmp.raoperationalmode=normal)
     * - Pre-configuration: Sets cmp.allowautomaticrenewal to 'false' and tests that the resetting of configuration has worked.
     * - Pre-configuration: Sets cmp.allowupdatewithsamekey to 'true'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Sends the request using HTTP and receives a response.
     * - Examines the response:
     *      - Checks that the response is not empty or null
     *      - Checks that the protection algorithm is sha1WithRSAEncryption
     *      - Checks that the signer is the expected CA
     *      - Verifies the response signature
     *      - Checks that the response's senderNonce is 16 bytes long
     *      - Checks that the request's senderNonce is the same as the response's recipientNonce
     *      - Checks that the request and the response has the same transactionID
     *      - Parses the response and checks that the parsing did not result in a 'null'
     *      - Checks that the CMP response message tag number is '23', indicating a CMP error message
     *      - Checks that the CMP response message contains the expected error details text
     * 
     * @throws Exception
     */
    @Test
    public void test02AutomaticUpdateNotAllowed() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test02AutomaticUpdateNotAllowed");
        }
        
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, false);
        this.cmpConfiguration.setKurAllowSameKey(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        //--------------- create the user and issue his first certificate -----------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate;
        try {
            certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        } catch (NoSuchEndEntityException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (CADoesntExistsException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (EjbcaException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (CesecoreException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        }
        assertNotNull("Failed to create a test certificate", certificate);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, null, null, pAlg, new DEROctetString(this.nonce));
        assertNotNull("Failed to generate a CMP renewal request", req);

        CMPCertificate[] extraCert = getCMPCert(certificate);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        final String expectedErrMsg = "Got request with status GENERATED (40), NEW, FAILED or INPROCESS required: " + RENEWAL_USERNAME + ".";
        assertEquals(expectedErrMsg, errMsg);

        if(log.isTraceEnabled()) {
            log.trace("<test02AutomaticUpdateNotAllowed");
        }

    }

    /**
     * Sends a KeyUpdateRequest concerning a revoked certificate. A CMP error message is expected and no certificate renewal.
     * 
     * - Pre-configuration: Sets the operational mode to client mode (cmp.raoperationalmode=normal)
     * - Pre-configuration: Sets cmp.allowautomaticrenewal to 'true' and tests that the resetting of configuration has worked.
     * - Pre-configuration: Sets cmp.allowupdatewithsamekey to 'true'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Revokes cert and tests that the revocation was successful
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Sends the request using HTTP and receives a response.
     * - Examines the response:
     *      - Checks that the response is not empty or null
     *      - Checks that the protection algorithm is sha1WithRSAEncryption
     *      - Checks that the signer is the expected CA
     *      - Verifies the response's signature
     *      - Checks that the response's senderNonce is 16 bytes long
     *      - Checks that the request's senderNonce is the same as the response's recipientNonce
     *      - Checks that the request and the response has the same transactionID
     *      - Parses the response and checks that the parsing did not result in a 'null'
     *      - Checks that the CMP response message tag number is '23', indicating a CMP error message
     *      - Checks that the CMP response message contain the expected error details text
     * 
     * @throws Exception
     */
    @Test
    public void test03UpdateRevokedCert() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test03UpdateRevokedCert");
        }
        
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        //--------------- create the user and issue his first certificate -----------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate;
        try {
            certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        } catch (NoSuchEndEntityException | CADoesntExistsException | AuthorizationDeniedException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } 
        assertNotNull("Failed to create a test certificate", certificate);
        
        this.internalCertificateStoreSession.setRevokeStatus(ADMIN, certificate, new Date(), RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION);
        assertTrue("Failed to revoke the test certificate", this.certificateStoreSession.isRevoked(CertTools.getIssuerDN(certificate), CertTools.getSerialNumber(certificate)));
        
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        KeyPair newKeyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, newKeyPair, false, null, null, pAlg, new DEROctetString(this.nonce));
        assertNotNull("Failed to generate a CMP renewal request", req);

        CMPCertificate[] extraCert = getCMPCert(certificate);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        final String expectedErrMsg = "The certificate attached to the PKIMessage in the extraCert field is not active.";
        assertEquals(expectedErrMsg, errMsg);

        if(log.isTraceEnabled()) {
            log.trace("<test03UpdateRevokedCert");
        }
    }
    
   
    
    /**
     * Sends a KeyUpdateRequest concerning a certificate that does not exist in the database. A CMP error message is expected and no certificate renewal.
     * 
     * - Pre-configuration: Sets the operational mode to client mode (cmp.raoperationalmode=normal)
     * - Pre-configuration: Sets cmp.allowautomaticrenewal to 'true' and tests that the resetting of configuration has worked.
     * - Pre-configuration: Sets cmp.allowupdatewithsamekey to 'true'
     * - Generates a self-signed certificate, fakecert
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using fakecert and attaches fakecert to the CMP request. Tests that the CMP request is still not null
     * - Sends the request using HTTP and receives an response.
     * - Examines the response:
     * 		- Checks that the response is not empty or null
     * 		- Checks that the protection algorithm is sha1WithRSAEncryption
     * 		- Checks that the signer is the expected CA
     * 		- Verifies the response signature
     * 		- Checks that the response's senderNonce is 16 bytes long
     * 		- Checks that the request's senderNonce is the same as the response's recipientNonce
     * 		- Checks that the request and the response has the same transactionID
     * 		- Parses the response and checks that the parsing did not result in a 'null'
     * 		- Checks that the CMP response message tag number is '23', indicating a CMP error message
     * 		- Checks that the CMP response message contain the expected error details text
     * 
     * @throws Exception
     */
    @Test
    public void test04UpdateKeyWithFakeCert() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test04UpdateKeyWithFakeCert");
        }
        
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        //--------------- create the user and issue his first certificate -----------------
        final String fakeUsername = "fakeuser";
        final X500Name fakeUserDN = new X500Name("CN=" + fakeUsername + ",C=SE");
        createUser(fakeUsername, fakeUserDN.toString(), "foo123");

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate fakeCert = CertTools.genSelfCert(fakeUserDN.toString(), 30, null, keys.getPrivate(), keys.getPublic(),
                    AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        assertNotNull("Failed to create a test certificate", fakeCert);
        
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        
        // Sending a request with a certificate that neither it nor the issuer CA is in the database
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, null, null, pAlg, new DEROctetString(this.nonce));
        assertNotNull("Failed to generate a CMP renewal request", req);

        CMPCertificate[] extraCert = getCMPCert(fakeCert);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        String expectedErrMsg = "Error. Received a CMP KeyUpdateRequest for a non-existing end entity";
        assertEquals(expectedErrMsg, errMsg);

        // sending another renewal request with a certificate issued by an existing CA but the certificate itself is not in the database        
        // A certificate, not in the database, issued by TestCA
        byte[] fakecertBytes = Base64.decode( (
                "MIIB6TCCAVKgAwIBAgIIIKF3bEBbbyQwDQYJKoZIhvcNAQELBQAwETEPMA0GA1UE" +
                "AwwGVGVzdENBMB4XDTEzMDMxMjExMTcyMVoXDTEzMDMyMjExMjcyMFowIDERMA8G" +
                "A1UEAwwIZmFrZXVzZXIxCzAJBgNVBAYTAlNFMFwwDQYJKoZIhvcNAQEBBQADSwAw" +
                "SAJBAKZlXrI3TwziiDK9/E1V4n6PCXhpRERSLWPEpRvRPWfpvazpq7R2UZZRq5i2" +
                "hrqKDbfLdAouh2J7AIlUZG3cdJECAwEAAaN/MH0wHQYDVR0OBBYEFCb2tsZTXOh7" +
                "FjjVXpSxkJ79P3tJMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAURmtK3gFt81Bp" +
                "3z+YZuzBm65Ja6IwDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMC" +
                "BggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOBgQAmclw6cwuQkiPSN4bHOP5S7bdU" +
                "+UKXLIkk1L84q0WQfblNzYkcDXMsxwJ1dv2Yd/dxIjtVjrhVIUrRMA70jtWs31CH" +
                "t9ofdgncIdtzZo49mLRQDwhTCApoLf0BCNb2rWpzCPWQTa97y0u5T65m7DAkBTV/" +
                "JAkFQIZCLSAci++qPA==").getBytes() );
        fakeCert = CertTools.getCertfromByteArray(fakecertBytes, Certificate.class);
        
        req = genRenewalReq(fakeUserDN, this.cacert, this.nonce, this.transid, keys, false, null, null, pAlg, new DEROctetString(this.nonce));
        assertNotNull("Failed to generate a CMP renewal request", req);

        extraCert = getCMPCert(fakeCert);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);
        
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        
        respObject = null;
        asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        body = respObject.getBody();
        assertEquals(23, body.getType());
        err = (ErrorMsgContent) body.getContent();
        errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        expectedErrMsg = "The certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
        assertEquals(expectedErrMsg, errMsg);
        
        
        if(log.isTraceEnabled()) {
            log.trace("<test04UpdateKeyWithFakeCert");
        }

    }

    /**
     * Sends a KeyUpdateRequest using the same old keys and the configurations is NOT to allow the use of the same key. 
     * A CMP error message is expected and no certificate renewal.
     * 
     * - Pre-configuration: Sets the operational mode to client mode (cmp.raoperationalmode=normal)
     * - Pre-configuration: Sets cmp.allowautomaticrenewal to 'true' and tests that the resetting of configuration has worked.
     * - Pre-configuration: Sets cmp.allowupdatewithsamekey to 'false'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Sends the request using HTTP and receives a response.
     * - Examines the response:
     * 		- Checks that the response is not empty or null
     * 		- Checks that the protection algorithm is sha1WithRSAEncryption
     * 		- Checks that the signer is the expected CA
     * 		- Verifies the response signature
     * 		- Checks that the response's senderNonce is 16 bytes long
     * 		- Checks that the request's senderNonce is the same as the response's recipientNonce
     * 		- Checks that the request and the response has the same transactionID
     * 		- Parses the response and checks that the parsing did not result in a 'null'
     * 		- Checks that the CMP response message tag number is '23', indicating a CMP error message
     * 		- Checks that the CMP response message contain the expected error details text
     * 
     * @throws Exception
     */
    @Test
    public void test05UpdateWithSameKeyNotAllowed() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test07UpdateWithSameKeyNotAllowed");
        }
        
        this.cmpConfiguration.setRAMode(this.cmpAlias, false);
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.cmpConfiguration.setKurAllowSameKey(this.cmpAlias, false);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        //--------------- create the user and issue his first certificate -----------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate;
        certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, null, null, pAlg, new DEROctetString(this.nonce));
        assertNotNull("Failed to generate a CMP renewal request", req);

        CMPCertificate[] extraCert = getCMPCert(certificate);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        final String expectedErrMsg = "Invalid key. The public key in the KeyUpdateRequest is the same as the public key in the existing end entity certificate";
        assertEquals(expectedErrMsg, errMsg);

        if(log.isTraceEnabled()) {
            log.trace("<test07UpdateWithSameKeyNotAllowed");
        }
    }

    /**
     * Sends a KeyUpdateRequest with a different key and the configurations is NOT to allow the use of the same keys. 
     * Successful operation is expected and a new certificate is received.
     * 
     * - Pre-configuration: Sets the operational mode to client mode (cmp.raoperationalmode=normal)
     * - Pre-configuration: Sets cmp.allowautomaticrenewal to 'true' and tests that the resetting of configuration has worked.
     * - Pre-configuration: Sets cmp.allowupdatewithsamekey to 'false'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Sends the request using HTTP and receives a response.
     * - Examines the response:
     * 		- Checks that the response is not empty or null
     * 		- Checks that the protection algorithm is sha1WithRSAEncryption
     * 		- Check that the signer is the expected CA
     * 		- Verifies the response signature
     * 		- Checks that the response's senderNonce is 16 bytes long
     * 		- Checks that the request's senderNonce is the same as the response's recipientNonce
     * 		- Checks that the request and the response has the same transactionID
     * 		- Obtains the certificate from the response
     * 		- Checks that the obtained certificate has the right subjectDN and issuerDN
     * 
     * @throws Exception
     */
    @Test
    public void test06UpdateWithDifferentKey() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test08UpdateWithDifferentKey");
        }
        
        this.cmpConfiguration.setRAMode(this.cmpAlias, false);
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.cmpConfiguration.setKurAllowSameKey(this.cmpAlias, false);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        //--------------- create the user and issue his first certificate -----------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate;
        certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);
        
        KeyPair newkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, newkeys, false, null, null, pAlg, new DEROctetString(this.nonce));
        assertNotNull("Failed to generate a CMP renewal request", req);
        CertReqMessages kur = (CertReqMessages) req.getBody().getContent();
        int reqId = kur.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();

        CMPCertificate[] extraCert = getCMPCert(certificate);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);
        //******************************************''''''
        final Signature sig = Signature.getInstance(req.getHeader().getProtectionAlg().getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        sig.initVerify(certificate.getPublicKey());
        sig.update(CmpMessageHelper.getProtectedBytes(req));
        boolean verified = sig.verify(req.getProtection().getBytes());
        assertTrue("Signing the message failed.", verified);
        //***************************************************
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkKurCertRepMessage(RENEWAL_USER_DN, this.cacert, resp, reqId);
        assertNotNull("Failed to renew the certificate", cert);
        assertTrue("The new certificate's keys are incorrect.", cert.getPublicKey().equals(newkeys.getPublic()));
        assertFalse("The new certificate's keys are the same as the old certificate's keys.", cert.getPublicKey().equals(keys.getPublic()));
        
        if(log.isTraceEnabled()) {
            log.trace("<test08UpdateWithDifferentKey");
        }
    }
    
    /**
     * Sends a KeyUpdateRequest in RA mode. 
     * Successful operation is expected and a new certificate is received.
     * 
     * - Pre-configuration: Sets the operational mode to RA mode (cmp.raoperationalmode=ra)
     * - Pre-configuration: Sets the cmp.authenticationmodule to 'EndEntityCertificate'
     * - Pre-configuration: Sets the cmp.authenticationparameters to 'TestCA'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Verifies the signature of the CMP request
     * - Sends the request using HTTP and receives an response.
     * - Examines the response:
     *      - Checks that the response is not empty or null
     *      - Checks that the protection algorithm is sha1WithRSAEncryption
     *      - Check that the signer is the expected CA
     *      - Verifies the response signature
     *      - Checks that the response's senderNonce is 16 bytes long
     *      - Checks that the request's senderNonce is the same as the response's recipientNonce
     *      - Checks that the request and the response has the same transactionID
     *      - Obtains the certificate from the response
     *      - Checks that the obtained certificate has the right subjectDN and issuerDN
     * 
     * @throws Exception
     */
    @Test
    public void test07RAMode() throws Exception {        
        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, TEST_CA_NAME);
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        //------------------ create the user and issue his first certificate -------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate;
        certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, RENEWAL_USER_DN, TEST_CA_DN, pAlg,
                new DEROctetString("CMPTESTPROFILE".getBytes()));
        assertNotNull("Failed to generate a CMP renewal request", req);
        final CertReqMessages kur = (CertReqMessages) req.getBody().getContent();
        int reqId = kur.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();    
        createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
        final KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken admToken = createAdminToken(admkeys, "cmpTestAdmin", "CN=cmpTestAdmin,C=SE");
        Certificate admCert = getCertFromCredentials(admToken);
        CMPCertificate[] extraCert = getCMPCert(admCert);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        //send request and recieve response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkKurCertRepMessage(RENEWAL_USER_DN, this.cacert, resp, reqId);
        assertNotNull("Failed to renew the certificate", cert);
        removeAuthenticationToken(admToken, admCert, "cmpTestAdmin");
    }
    
    /**
     * Performs a CMP request in RA mode where the requesting admin isn't issued by the same CA. Should fail due to missing authorization. 
     * @throws OperatorCreationException 
     */
    @Test
    public void testRAModeForAdminFromDifferentCa() throws AuthorizationDeniedException, CADoesntExistsException, ApprovalException,
            CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException,
            EndEntityProfileValidationException, WaitingForApprovalException, InvalidAlgorithmParameterException, IllegalKeyException,
            CertificateCreateException, CertificateRevokeException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException, InvalidKeyException,
            CertificateEncodingException, NoSuchAlgorithmException, SignatureException, RoleNotFoundException, NoSuchProviderException,
            SecurityException, IOException, CertificateParsingException, CertPathValidatorException, CouldNotRemoveEndEntityException, CAExistsException, OperatorCreationException {
        final String cmpAdminUsername = "cmpTestAdmin";
        final String cmpAdminDn = "CN=" + cmpAdminUsername +",C=SE";
        final String cmpAdminPassword = "foo123";
        final String differentCaDn = "CN=testRAModeForAdminFromDifferentCa";
        
        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, TEST_CA_NAME);
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        //------------------ create the user and issue his first certificate -------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate;
        certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, RENEWAL_USER_DN, TEST_CA_DN, pAlg,
                new DEROctetString("CMPTESTPROFILE".getBytes()));
        assertNotNull("Failed to generate a CMP renewal request", req);
        //Create a second CA to issue the admin certificate
        CA differentX509ca = CaTestUtils.createTestX509CA(differentCaDn, null, false,
                X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        caSession.addCA(ADMIN, differentX509ca);
        //Create the admin user 
        createUser(cmpAdminUsername, cmpAdminDn, cmpAdminPassword, differentX509ca.getCAId());
        final KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken admToken = createAdminToken(admkeys, cmpAdminUsername, cmpAdminDn);
        Certificate admCert = getCertFromCredentials(admToken);
        try {
            CMPCertificate[] extraCert = getCMPCert(admCert);
            req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(),
                    BouncyCastleProvider.PROVIDER_NAME);
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            //send request and recieve response
            byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
            checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            PKIMessage respObject = null;
            ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
            try {
                respObject = PKIMessage.getInstance(asn1InputStream.readObject());
            } finally {
                asn1InputStream.close();
            }
            assertNotNull(respObject);
            final PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            final String expectedErrMsg = "The certificate attached to the PKIMessage in the extraCert field is not valid - Trust anchor for certification path not found.";
            assertEquals(expectedErrMsg, errMsg);
        } finally {
            removeTestCA(differentX509ca.getCAId());
            removeAuthenticationToken(admToken, admCert, "cmpTestAdmin");
        }
    }


    
    /**
     * Sends a KeyUpdateRequest in RA mode and the request sender is not a known end entity
     * A CMP error message is expected and no certificate renewal.
     * 
     * - Pre-configuration: Sets the operational mode to client mode (cmp.raoperationalmode=normal)
     * - Pre-configuration: Sets the cmp.authenticationmodule to 'EndEntityCertificate'
     * - Pre-configuration: Sets the cmp.authenticationparameters to 'TestCA'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Verifies the signature of the CMP request
     * - Sends the request using HTTP and receives an response.
     * - Examines the response:
     *      - Checks that the response is not empty or null
     *      - Checks that the protection algorithm is sha1WithRSAEncryption
     *      - Check that the signer is the expected CA
     *      - Verifies the response signature
     *      - Checks that the response's senderNonce is 16 bytes long
     *      - Checks that the request's senderNonce is the same as the response's recipientNonce
     *      - Checks that the request and the response has the same transactionID
     *      - Parse the response and make sure that the parsing did not result in a 'null'
     *      - Check that the CMP response message tag number is '23', indicating a CMP error message
     *      - Check that the CMP response message contain the expected error details text
     * 
     * @throws Exception
     */
    @Test
    public void test08RAModeUnknownAdmin() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace("test08RAModeUnknownAdmin()");
        }
        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, TEST_CA_NAME);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        //------------------ create the user and issue his first certificate -------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, RENEWAL_USER_DN, TEST_CA_DN, pAlg,
                new DEROctetString("CMPTESTPROFILE".getBytes()));
        assertNotNull("Failed to generate a CMP renewal request", req);        
        CMPCertificate[] extraCert = getCMPCert(certificate);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        //send request and recieve response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);
        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        final String expectedErrMsg = "'" + RENEWAL_USER_DN + "' is not an authorized administrator.";
        assertEquals(expectedErrMsg, errMsg);
        if(log.isTraceEnabled()) {
            log.trace("<test08RAModeUnknownAdmin()");
        }

    }
    
    /**
     * Sends a KeyUpdateRequest in RA mode without filling the 'issuerDN' field in the request. 
     * Successful operation is expected and a new certificate is received.
     * 
     * - Pre-configuration: Sets the operational mode to RA mode (cmp.raoperationalmode=ra)
     * - Pre-configuration: Sets the cmp.authenticationmodule to 'EndEntityCertificate'
     * - Pre-configuration: Sets the cmp.authenticationparameters to 'TestCA'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Verifies the signature of the CMP request
     * - Sends the request using HTTP and receives an response.
     * - Examines the response:
     *      - Checks that the response is not empty or null
     *      - Checks that the protection algorithm is sha1WithRSAEncryption
     *      - Check that the signer is the expected CA
     *      - Verifies the response signature
     *      - Checks that the response's senderNonce is 16 bytes long
     *      - Checks that the request's senderNonce is the same as the response's recipientNonce
     *      - Checks that the request and the response has the same transactionID
     *      - Obtains the certificate from the response
     *      - Checks that the obtained certificate has the right subjectDN and issuerDN
     * 
     * @throws Exception
     */
    @Test
    public void test09RANoIssuer() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace("test11RANoIssuer()");
        }
        
        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, TEST_CA_NAME);
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        //------------------ create the user and issue his first certificate -------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, RENEWAL_USER_DN, null, pAlg, new DEROctetString("CMPTESTPROFILE".getBytes()));
        assertNotNull("Failed to generate a CMP renewal request", req);
        CertReqMessages kur = (CertReqMessages) req.getBody().getContent();
        int reqId = kur.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        
        createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken admToken = createAdminToken(admkeys, "cmpTestAdmin", "CN=cmpTestAdmin,C=SE");
        Certificate admCert = getCertFromCredentials(admToken);
        CMPCertificate[] extraCert = getCMPCert(admCert);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);

        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        //send request and recieve response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkKurCertRepMessage(RENEWAL_USER_DN, this.cacert, resp, reqId);
        assertNotNull("Failed to renew the certificate", cert);
        
        removeAuthenticationToken(admToken, admCert, "cmpTestAdmin");
        
        if(log.isTraceEnabled()) {
            log.trace("<test11RANoIssuer()");
        }

    }
    
    /**
     * Sends a KeyUpdateRequest in RA mode with neither subjectDN nor issuerDN are set in the request. 
     * A CMP error message is expected and no certificate renewal.
     * 
     * - Pre-configuration: Sets the operational mode to client mode (cmp.raoperationalmode=normal)
     * - Pre-configuration: Sets the cmp.authenticationmodule to 'EndEntityCertificate'
     * - Pre-configuration: Sets the cmp.authenticationparameters to 'TestCA'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Verifies the signature of the CMP request
     * - Sends the request using HTTP and receives an response.
     * - Examines the response:
     *      - Checks that the response is not empty or null
     *      - Checks that the protection algorithm is sha1WithRSAEncryption
     *      - Check that the signer is the expected CA
     *      - Verifies the response signature
     *      - Checks that the response's senderNonce is 16 bytes long
     *      - Checks that the request's senderNonce is the same as the response's recipientNonce
     *      - Checks that the request and the response has the same transactionID
     *      - Parse the response and make sure that the parsing did not result in a 'null'
     *      - Check that the CMP response message tag number is '23', indicating a CMP error message
     *      - Check that the CMP response message contain the expected error details text
     * 
     * @throws Exception
     */
    @Test
    public void test10RANoIssuerNoSubjectDN() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace("test12RANoIssuerNoSubjetDN()");
        }
        
        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, TEST_CA_NAME);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        //------------------ create the user and issue his first certificate -------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, null, null, pAlg, new DEROctetString("CMPTESTPROFILE".getBytes()));
        assertNotNull("Failed to generate a CMP renewal request", req);
        
        createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken admToken = createAdminToken(admkeys, "cmpTestAdmin", "CN=cmpTestAdmin,C=SE");
        Certificate admCert = getCertFromCredentials(admToken);
        CMPCertificate[] extraCert = getCMPCert(admCert);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);

        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        //send request and recieve response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        final String expectedErrMsg = "Error. Received a CMP KeyUpdateRequest for a non-existing end entity";
        assertEquals(expectedErrMsg, errMsg);

        removeAuthenticationToken(admToken, admCert, "cmpTestAdmin");
        
        if(log.isTraceEnabled()) {
            log.trace("<test12RANoIssuerNoSubjectDN()");
        }

    }
    
    /**
     * Sends a KeyUpdateRequest in RA mode when there are more than one authentication module configured. 
     * Successful operation is expected and a new certificate is received.
     * 
     * - Pre-configuration: Sets the operational mode to RA mode (cmp.raoperationalmode=ra)
     * - Pre-configuration: Sets the cmp.authenticationmodule to "HMAC;DnPartPwd;EndEntityCertificate"
     * - Pre-configuration: Sets the cmp.authenticationparameters to "-;OU;TestCA"
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Verifies the signature of the CMP request
     * - Sends the request using HTTP and receives an response.
     * - Examines the response:
     *      - Checks that the response is not empty or null
     *      - Checks that the protection algorithm is sha1WithRSAEncryption
     *      - Check that the signer is the expected CA
     *      - Verifies the response signature
     *      - Checks that the response's senderNonce is 16 bytes long
     *      - Checks that the request's senderNonce is the same as the response's recipientNonce
     *      - Checks that the request and the response has the same transactionID
     *      - Obtains the certificate from the response
     *      - Checks that the obtained certificate has the right subjectDN and issuerDN
     * 
     * @throws Exception
     */
    @Test
    public void test11RAMultipleAuthenticationModules() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace("test13RAMultipleAuthenticationModules");
        }
        
        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        String authmodules = CmpConfiguration.AUTHMODULE_HMAC + ";" + CmpConfiguration.AUTHMODULE_DN_PART_PWD + ";" + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, authmodules);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, "-;OU;TestCA");
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        //------------------ create the user and issue his first certificate -------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, RENEWAL_USER_DN, null, pAlg, new DEROctetString("CMPTESTPROFILE".getBytes()));
        assertNotNull("Failed to generate a CMP renewal request", req);
        CertReqMessages kur = (CertReqMessages) req.getBody().getContent();
        int reqId = kur.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        
        createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken admToken = createAdminToken(admkeys, "cmpTestAdmin", "CN=cmpTestAdmin,C=SE");
        Certificate admCert = getCertFromCredentials(admToken);
        CMPCertificate[] extraCert = getCMPCert(admCert);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);

        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        //send request and recieve response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkKurCertRepMessage(RENEWAL_USER_DN, this.cacert, resp, reqId);
        assertNotNull("Failed to renew the certificate", cert);
        
        removeAuthenticationToken(admToken, admCert, "cmpTestAdmin");
        
        if(log.isTraceEnabled()) {
            log.trace("<test13RAMultipleAuthenticationModules()");
        }

    }

    /**
     * Sends a KeyUpdateRequest in RA mode when the authentication module is NOT set to 'EndEntityCertificate'. 
     * A CMP error message is expected and no certificate renewal.
     * 
     * - Pre-configuration: Sets the operational mode to RA mode (cmp.raoperationalmode=ra)
     * - Pre-configuration: Sets the cmp.authenticationmodule to 'DnPartPwd'
     * - Pre-configuration: Sets the cmp.authenticationparameters to 'OU'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Verifies the signature of the CMP request
     * - Sends the request using HTTP and receives an response.
     * - Examines the response:
     *      - Checks that the response is not empty or null
     *      - Checks that the protection algorithm is sha1WithRSAEncryption
     *      - Check that the signer is the expected CA
     *      - Verifies the response signature
     *      - Checks that the response's senderNonce is 16 bytes long
     *      - Checks that the request's senderNonce is the same as the response's recipientNonce
     *      - Checks that the request and the response has the same transactionID
     *      - Obtains the certificate from the response
     *      - Checks that the obtained certificate has the right subjectDN and issuerDN
     * 
     * @throws Exception
     */
    @Test
    public void test12ECCNotSetInRA() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace("test12ECCNotSetInRA()");
        }
        
        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_DN_PART_PWD);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, "OU");
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.cmpConfiguration.setKurAllowSameKey(this.cmpAlias, true);
        this.cmpConfiguration.setCMPDefaultCA(this.cmpAlias, "");
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        //------------------ create the user and issue his first certificate -------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, RENEWAL_USER_DN, null, pAlg, null);
        assertNotNull("Failed to generate a CMP renewal request", req);
        
        createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken admToken = createAdminToken(admkeys, "cmpTestAdmin", "CN=cmpTestAdmin,C=SE");
        final Certificate admCert = getCertFromCredentials(admToken);
        CMPCertificate[] extraCert = getCMPCert(admCert);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);

        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        //send request and recieve response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        final String expectedErrMsg = "EndEntityCertificate authentication module is not configured. For a KeyUpdate request to be authentication " +
        		                        "in RA mode, EndEntityCertificate authentication module has to be set and configured";
        assertEquals(expectedErrMsg, errMsg);

        removeAuthenticationToken(admToken, admCert, "cmpTestAdmin");
        
        if(log.isTraceEnabled()) {
            log.trace("<test12ECCNotSetInRA()");
        }

    }
 
    /**
     * Sends a KeyUpdateRequest by an admin concerning a certificate of another EndEntity in client mode. 
     * If the CA enforces unique public key, a CMP error message is expected and no certificate renewal.
     * If the CA does not enforce unique public key, a certificate will be renewed, though not the expected EndEntity certificate, but the admin certificate is renewed.
     * 
     * - Pre-configuration: Sets the operational mode to client mode (cmp.raoperationalmode=normal)
     * - Pre-configuration: Sets the cmp.authenticationmodule to 'EndEntityCertificate'
     * - Pre-configuration: Sets the cmp.authenticationparameters to 'TestCA'
     * - Pre-configuration: Sets the cmp.allowautomatickeyupdate to 'true'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using cert and attaches cert to the CMP request. Tests that the CMP request is still not null
     * - Verifies the signature of the CMP request
     * - Sends the request using HTTP and receives an response.
     * - Examines the response:
     *      - Checks that the response is not empty or null
     *      - Checks that the protection algorithm is sha1WithRSAEncryption
     *      - Check that the signer is the expected CA
     *      - Verifies the response signature
     *      - Checks that the response's senderNonce is 16 bytes long
     *      - Checks that the request's senderNonce is the same as the response's recipientNonce
     *      - Checks that the request and the response has the same transactionID
     *      - Obtains the certificate from the response
     *      - Checks that the obtained certificate has the right subjectDN and issuerDN
     * 
     * @throws Exception
     */
    @Test
    public void test13AdminInClientMode() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace("test09RAMode()");
        }
        
        this.cmpConfiguration.setRAMode(this.cmpAlias, false);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, TEST_CA_NAME);
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        //------------------ create the user and issue his first certificate -------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, RENEWAL_USER_DN, TEST_CA_DN, pAlg, new DEROctetString("CMPTESTPROFILE".getBytes()));
        assertNotNull("Failed to generate a CMP renewal request", req);
        //int reqId = req.getBody().getKur().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        
        createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken admToken = createAdminToken(admkeys, "cmpTestAdmin", "CN=cmpTestAdmin,C=SE");
        Certificate admCert = getCertFromCredentials(admToken);
        CMPCertificate[] extraCert = getCMPCert(admCert);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        //send request and recieve response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);
        
        
        CAInfo cainfo = this.caSession.getCAInfo(ADMIN, this.caid);
        if(cainfo.isDoEnforceUniquePublicKeys()) {
            final PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            final String expectedErrMsg = "User 'cmpTestAdmin' is not allowed to use same key as another user is using.";
            assertEquals(expectedErrMsg, errMsg);
        } else {
            PKIBody body = respObject.getBody();
            int tag = body.getType();
            assertEquals(8, tag);
            CertRepMessage c = (CertRepMessage) body.getContent();
            assertNotNull(c);            
            CMPCertificate cmpcert = c.getResponse()[0].getCertifiedKeyPair().getCertOrEncCert().getCertificate();
            assertNotNull(cmpcert);
            X509Certificate cert = CertTools.getCertfromByteArray(cmpcert.getEncoded(), X509Certificate.class);
            assertNotNull("Failed to renew the certificate", cert);
            assertEquals("CN=cmpTestAdmin, C=SE", cert.getSubjectX500Principal().toString());
        }

        removeAuthenticationToken(admToken, admCert, "cmpTestAdmin");

        if(log.isTraceEnabled()) {
            log.trace("<test09RAMode()");
        }
    }
    
    /**
     * Sends a KeyUpdateRequest by an EndEntity concerning its own certificate in RA mode. 
     * A CMP error message is expected and no certificate renewal.
     * 
     * @throws Exception
     */
    @Test
    public void test14EndEntityRequestingInRAMode() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test14KeyUpdateRequestOK");
        }
        
        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, TEST_CA_NAME);
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.cmpConfiguration.setKurAllowSameKey(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        //--------------- create the user and issue his first certificate -----------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate;
        try {
            certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        } catch (NoSuchEndEntityException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (CADoesntExistsException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (EjbcaException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (CesecoreException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        }
        assertNotNull("Failed to create a test certificate", certificate);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, RENEWAL_USER_DN, CertTools.getSubjectDN(cacert), pAlg, new DEROctetString(this.nonce));
        assertNotNull("Failed to generate a CMP renewal request", req);

        CMPCertificate[] extraCert = getCMPCert(certificate);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        
        final String expectedErrMsg = "'CN=certRenewalUser,O=PrimeKey Solutions AB,C=SE' is not an authorized administrator.";
        assertEquals(expectedErrMsg, errMsg);
        
        if(log.isTraceEnabled()) {
            log.trace("<test14KeyUpdateRequestOK");
        }
    }


    
    /**
     * Tests the possibility to use different signature algorithms in CMP requests and responses.
     * 
     * A KeyUpdate request, signed using ECDSA with SHA256, is sent to a CA that uses RSA with SHA256 as signature algorithm.
     * The expected response is signed by RSA with SHA256.
     * 
     * @throws Exception
     */
    @Test
    public void test15KeyUpdateMixAlgorithms() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test15KeyUpdateMixAlgorithms");
        }
        
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.cmpConfiguration.setKurAllowSameKey(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        //--------------- create the user and issue his first certificate -----------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        KeyPair keys = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        final Certificate certificate;
        try {
            certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        } catch (NoSuchEndEntityException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (CADoesntExistsException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (EjbcaException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        } catch (CesecoreException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        }
        assertNotNull("Failed to create a test certificate", certificate);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, null, null, pAlg, new DEROctetString(this.nonce));
        assertNotNull("Failed to generate a CMP renewal request", req);
        CertReqMessages kur = (CertReqMessages) req.getBody().getContent();
        int reqId = kur.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        CMPCertificate[] extraCert = getCMPCert(certificate);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA256, BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
        checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, true, null, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
        X509Certificate cert = checkKurCertRepMessage(RENEWAL_USER_DN, this.cacert, resp, reqId);
        assertNotNull("Failed to renew the certificate", cert);
        assertTrue("The new certificate's keys are incorrect.", cert.getPublicKey().equals(keys.getPublic()));
        
        if(log.isTraceEnabled()) {
            log.trace("<test15KeyUpdateMixAlgorithms");
        }

    }

    private static CMPCertificate[] getCMPCert(Certificate cert) throws CertificateEncodingException {
        return new CMPCertificate[] { new CMPCertificate(org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded())) };
    }

    private EndEntityInformation createUser(String userName, String subjectDN, String password)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException, CADoesntExistsException,
            ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException {
        return createUser(userName, subjectDN, password, this.caid);
    }

    private static X509Certificate getCertFromCredentials(AuthenticationToken authToken) {
        Set<?> inputcreds = authToken.getCredentials();
        if (inputcreds != null) {
            for (Object object : inputcreds) {
                if (object instanceof X509Certificate) {
                    return (X509Certificate) object;
                }
            }
        }
        return null;
    }

    private AuthenticationToken createAdminToken(KeyPair keys, String name, String dn) throws RoleNotFoundException,
            AuthorizationDeniedException {
        Set<Principal> principals = new HashSet<Principal>();
        X500Principal p = new X500Principal(dn);
        principals.add(p);
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        AuthenticationToken token = createTokenWithCert(name, subject, keys);
        X509Certificate cert = (X509Certificate) token.getCredentials().iterator().next();

        // Initialize the role mgmt system with this role that is allowed to edit roles
        String roleName = getRoleName();
        final Role role = roleSession.getRole(ADMIN, null, roleName);
        roleMemberSession.persist(ADMIN, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                CertTools.getIssuerDN(cert).hashCode(), X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(), CertTools.getSerialNumberAsString(cert), role.getRoleId(), null));
        return token;
    }

    private AuthenticationToken createTokenWithCert(String adminName, AuthenticationSubject subject, KeyPair keys) {

        // A small check if we have added a "fail" credential to the subject.
        // If we have we will return null, so we can test authentication failure.
        Set<?> usercredentials = subject.getCredentials();
        if ((usercredentials != null) && (usercredentials.size() > 0)) {
            Object o = usercredentials.iterator().next();
            if (o instanceof String) {
                String str = (String) o;
                if (StringUtils.equals("fail", str)) {
                    return null;
                }
            }
        }

        final X509Certificate certificate;
        // If there was no certificate input, create a self signed
        String dn = "C=SE,O=Test,CN=Test"; // default
        // If we have created a subject with an X500Principal we will use this DN to create the dummy certificate.
        {
            final Set<Principal> principals = subject.getPrincipals();
            if ((principals != null) && (principals.size() > 0)) {
                Principal p = principals.iterator().next();
                if (p instanceof X500Principal) {
                    X500Principal xp = (X500Principal) p;
                    dn = xp.getName();
                }
            }
        }
        try {
            if (!endEntityManagementSession.existsUser(adminName)) {
                createUser(adminName, dn, "foo123");
            }
        } catch (Exception e) {
            throw new IllegalStateException("Error encountered when creating admin user", e);
        }
        try {
            certificate = (X509Certificate) this.signSession.createCertificate(ADMIN, adminName, "foo123", new PublicKeyWrapper(keys.getPublic()));
        } catch (EjbcaException | AuthorizationDeniedException | CesecoreException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        }
        // We cannot use the X509CertificateAuthenticationToken here, since it can only be used internally in a JVM.
        AuthenticationToken result = new TestX509CertificateAuthenticationToken(certificate);
        return result;
    }

    private void removeAuthenticationToken(AuthenticationToken authToken, Certificate cert, String adminName) throws RoleNotFoundException,
            AuthorizationDeniedException, ApprovalException, NoSuchEndEntityException, WaitingForApprovalException, CouldNotRemoveEndEntityException {
        if (cert!=null) {
            final Role role = roleSession.getRole(ADMIN, null, getRoleName());
            if (role!=null) {
                final String tokenMatchValue = CertTools.getSerialNumberAsString(cert);
                for (final RoleMember roleMember : roleMemberSession.getRoleMembersByRoleId(ADMIN, role.getRoleId())) {
                    if (tokenMatchValue.equals(roleMember.getTokenMatchValue())) {
                        roleMemberSession.remove(ADMIN, roleMember.getId());
                    }
                }
            }
        }
        endEntityManagementSession.revokeAndDeleteUser(ADMIN, adminName, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        internalCertificateStoreSession.removeCertificate(cert);
    }
    
    /**
     * Since Key Update Requests are parsed slightly differently in client and RA mode, the previous update request is repeated in RA mode.
     * 
     * RFC4210 states in ch. 5.3.5:
     * "[...] This message is intended to be used to request updates to existing (non-revoked and non-expired) certificates [...]" 
     * 
     * @throws Exception
     */
    @Test
    public void testUpdateRevokedCertInRaMode() throws Exception {
        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, TEST_CA_NAME);
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        //------------------ create the user and issue his first certificate -------------
        createUser(RENEWAL_USERNAME, RENEWAL_USER_DN.toString(), "foo123");
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final Certificate certificate;
        certificate = this.signSession.createCertificate(ADMIN, RENEWAL_USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create a test certificate", certificate);
        endEntityManagementSession.revokeCert(ADMIN, CertTools.getSerialNumber(certificate), new Date(), CertTools.getIssuerDN(certificate),
                RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION, false);
        assertTrue("Failed to revoke the test certificate", certificateStoreSession.isRevoked(CertTools.getIssuerDN(certificate), CertTools.getSerialNumber(certificate)));      
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, RENEWAL_USER_DN, TEST_CA_DN, pAlg, new DEROctetString("CMPTESTPROFILE".getBytes()));
        assertNotNull("Failed to generate a CMP renewal request", req);      
        final String testAdminName = "cmpTestAdmin";
        createUser(testAdminName, "CN="+testAdminName, "foo123");
        final KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken admToken = createAdminToken(admkeys, testAdminName, "CN="+testAdminName);
        Certificate admCert = getCertFromCredentials(admToken);
        try {
            CMPCertificate[] extraCert = getCMPCert(admCert);
            req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(),
                    BouncyCastleProvider.PROVIDER_NAME);
            byte[] ba = req.toASN1Primitive().getEncoded();
            //send request and recieve response
            byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
            checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            PKIMessage respObject = PKIMessage.getInstance(resp);
            assertNotNull("No respose object was received.", respObject);
            final PKIBody body = respObject.getBody();
            assertEquals("Response body was of incorrect type.", CmpPKIBodyConstants.ERRORMESSAGE, body.getType());
        } finally {
            removeAuthenticationToken(admToken, admCert, testAdminName);
        }
    }
    
    /**
     * Test updating an expired certificate. Should fail:
     * 
     * RFC4210 states in ch. 5.3.5:
     * "[...] This message is intended to be used to request updates to existing (non-revoked and non-expired) certificates [...]" 
     * 
     */
    @Test
    public void testUpdateExpiredCert() throws Exception {
        //Create a certificate profile that allows validity override
        final String profileName = "testUpdateExpiredCert";
        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setAllowValidityOverride(true);
        int certificateProfileId = certProfileSession.addCertificateProfile(ADMIN, profileName, certificateProfile);
        EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(ADMIN, profileName, endEntityProfile);
        try {
            this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
            this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
            final String password = "foo123";
            //--------------- create the user and issue its certificate, expired -----------------
            endEntityManagementSession.addUser(ADMIN, RENEWAL_USERNAME, password, RENEWAL_USER_DN.toString(), "rfc822name=" + RENEWAL_USERNAME + "@primekey.se",
                    RENEWAL_USERNAME + "@primekey.se", true, endEntityProfileId, certificateProfileId, EndEntityTypes.ENDUSER.toEndEntityType(),
                    SecConst.TOKEN_SOFT_PEM, 0, this.caid);

            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            SimpleRequestMessage expiredReq = new SimpleRequestMessage(keys.getPublic(), RENEWAL_USERNAME, password,
                    new Date(System.currentTimeMillis() - 1000 * 60 * 60 * 12));
            EndEntityInformation endEntity = endEntityAccessSession.findUser(ADMIN, RENEWAL_USERNAME);
            X509ResponseMessage responseMessage = (X509ResponseMessage) certificateCreateSession.createCertificate(ADMIN, endEntity, expiredReq,
                    X509ResponseMessage.class, signSession.fetchCertGenParams());
            Certificate certificate = responseMessage.getCertificate();
            try {
                CertTools.checkValidity(certificate, new Date(System.currentTimeMillis() + 1000 * 60 * 60));
                fail("Certificate is not expired, test cannot continue.");
            } catch (CertificateExpiredException e) {
                // NOPMD: As it should be
            }
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            KeyPair newKeyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, newKeyPair, false, null, null, pAlg,
                    new DEROctetString(this.nonce));
            assertNotNull("Failed to generate a CMP renewal request", req);
            CMPCertificate[] extraCert = getCMPCert(certificate);
            req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(),
                    BouncyCastleProvider.PROVIDER_NAME);
            assertNotNull(req);
            byte[] ba = req.toASN1Primitive().getEncoded();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
            checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            PKIMessage respObject = PKIMessage.getInstance(resp);
            assertNotNull(respObject);
            final PKIBody body = respObject.getBody();
            assertEquals("Response body was of incorrect type.", CmpPKIBodyConstants.ERRORMESSAGE, body.getType());
        } finally {
            certProfileSession.removeCertificateProfile(ADMIN, profileName);
            endEntityProfileSession.removeEndEntityProfile(ADMIN, profileName);
        }
    }
    
    /**
     * Tests updating an expired certificate, but this time in RA mode. 
     * 
     * RFC4210 states in ch. 5.3.5:
     * "[...] This message is intended to be used to request updates to existing (non-revoked and non-expired) certificates [...]" 
     * 
     * @throws Exception
     */
    @Test
    public void testUpdateExpiredCertInRaMode() throws Exception {
        final String profileName = "testUpdateExpiredCertInRaMode";
        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setAllowValidityOverride(true);
        int certificateProfileId = certProfileSession.addCertificateProfile(ADMIN, profileName, certificateProfile);
        EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(ADMIN, profileName, endEntityProfile);

        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, TEST_CA_NAME);
        this.cmpConfiguration.setKurAllowAutomaticUpdate(this.cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        //------------------ create the user and issue his first certificate -------------
        final String password = "foo123";
        //--------------- create the user and issue its certificate, expired -----------------
        endEntityManagementSession.addUser(ADMIN, RENEWAL_USERNAME, password, RENEWAL_USER_DN.toString(), "rfc822name=" + RENEWAL_USERNAME + "@primekey.se",
                RENEWAL_USERNAME + "@primekey.se", true, endEntityProfileId, certificateProfileId, EndEntityTypes.ENDUSER.toEndEntityType(),
                SecConst.TOKEN_SOFT_PEM, 0, this.caid);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage expiredReq = new SimpleRequestMessage(keys.getPublic(), RENEWAL_USERNAME, password,
                new Date(System.currentTimeMillis() - 1000 * 60 * 60 * 12));
        EndEntityInformation endEntity = endEntityAccessSession.findUser(ADMIN, RENEWAL_USERNAME);
        X509ResponseMessage responseMessage = (X509ResponseMessage) certificateCreateSession.createCertificate(ADMIN, endEntity, expiredReq,
                X509ResponseMessage.class, signSession.fetchCertGenParams());
        try {
            CertTools.checkValidity(responseMessage.getCertificate(), new Date(System.currentTimeMillis() + 1000 * 60 * 60));
            fail("Certificate is not expired, test cannot continue.");
        } catch (CertificateExpiredException e) {
            // NOPMD: As it should be
        }
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, keys, false, RENEWAL_USER_DN, TEST_CA_DN, pAlg, new DEROctetString("CMPTESTPROFILE".getBytes()));
        assertNotNull("Failed to generate a CMP renewal request", req);      
        final String testAdminName = "cmpTestAdmin";
        createUser(testAdminName, "CN="+testAdminName, "foo123");
        final KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken admToken = createAdminToken(admkeys, testAdminName, "CN="+testAdminName);
        Certificate admCert = getCertFromCredentials(admToken);
        try {
            CMPCertificate[] extraCert = getCMPCert(admCert);
            req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(),
                    BouncyCastleProvider.PROVIDER_NAME);
            byte[] ba = req.toASN1Primitive().getEncoded();
            //send request and recieve response
            byte[] resp = sendCmpHttp(ba, 200, this.cmpAlias);
            checkCmpResponseGeneral(resp, TEST_CA_DN, RENEWAL_USER_DN, this.cacert, this.nonce, this.transid, false, null,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            PKIMessage respObject = PKIMessage.getInstance(resp);
            assertNotNull("No respose object was received.", respObject);
            final PKIBody body = respObject.getBody();
            assertEquals("Response body was of incorrect type.", CmpPKIBodyConstants.ERRORMESSAGE, body.getType());
        } finally {
            removeAuthenticationToken(admToken, admCert, testAdminName);
            certProfileSession.removeCertificateProfile(ADMIN, profileName);
            endEntityProfileSession.removeEndEntityProfile(ADMIN, profileName);
        }
    }
    
}
