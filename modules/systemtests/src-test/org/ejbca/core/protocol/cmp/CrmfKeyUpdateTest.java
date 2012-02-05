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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.ObjectNotFoundException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.CertificateCreationException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfigurationHolder;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.novosec.pkix.asn1.cmp.CertOrEncCert;
import com.novosec.pkix.asn1.cmp.CertRepMessage;
import com.novosec.pkix.asn1.cmp.CertResponse;
import com.novosec.pkix.asn1.cmp.CertifiedKeyPair;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.PKIStatusInfo;
import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMessages;
import com.novosec.pkix.asn1.crmf.CertReqMsg;
import com.novosec.pkix.asn1.crmf.CertRequest;
import com.novosec.pkix.asn1.crmf.CertTemplate;
import com.novosec.pkix.asn1.crmf.OptionalValidity;
import com.novosec.pkix.asn1.crmf.POPOSigningKey;
import com.novosec.pkix.asn1.crmf.ProofOfPossession;

/**
 * This will test the different cmp authentication modules.
 * 
 * @version $Id$
 *
 */
public class CrmfKeyUpdateTest extends CmpTestCase {

    
    private static final Logger log = Logger.getLogger(CrmfKeyUpdateTest.class);

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrmfKeyUpdateTest"));
    
    private String username;
    private String userDN;
    private String issuerDN;
    private byte[] nonce;
    private byte[] transid;
    private int caid;
    private Certificate cacert;
    
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private UserAdminSessionRemote userAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UserAdminSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private ConfigurationSessionRemote confSession = JndiHelper.getRemoteSession(ConfigurationSessionRemote.class); //EjbRemoteHelper.INSTANCE.getConfigurationSession();
    private CertificateStoreSession certStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    
    @Before
    public void setUp() throws Exception {
        super.setUp();

        username = "certRenewalUser";
        userDN = "CN="+username+",O=PrimeKey Solutions AB,C=SE";
        issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
        nonce = CmpMessageHelper.createSenderNonce();
        transid = CmpMessageHelper.createSenderNonce();


        CryptoProviderTools.installBCProvider();
        try {
            setCAID();
            assertFalse("caid if 0", caid==0);
            setCaCert();
            assertNotNull("cacert is null", cacert);
        } catch (CADoesntExistsException e) {
            log.error("Failed to find CA. " + e.getLocalizedMessage());
        } catch (AuthorizationDeniedException e) {
            log.error("Failed to find CA. " + e.getLocalizedMessage());
        }
        
        // Initialize config in here
        EjbcaConfigurationHolder.instance();
        
        confSession.backupConfiguration();
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");

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
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true"));
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY, "true");

        
        //--------------- create the user and issue his first certificate -----------------
        createUser(username, userDN, "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = null;
        try {
            certificate = (X509Certificate) signSession.createCertificate(admin, username, "foo123", keys.getPublic());
        } catch (ObjectNotFoundException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (CADoesntExistsException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (EjbcaException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (AuthorizationDeniedException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (CesecoreException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        }
        assertNotNull("Failed to create a test certificate", certificate);

        
        
        PKIMessage req = genRenewalReq(keys, false);
        assertNotNull("Failed to generate a CMP renewal request", req);
        int reqId = req.getBody().getKur().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        req.getHeader().setProtectionAlg(pAlg);      
        req.getHeader().setSenderKID(new DEROctetString(nonce));
        addExtraCert(req, certificate);
        signPKIMessage(req, keys);
        assertNotNull(req);
        /*
        final Signature sig = Signature.getInstance(req.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
        sig.initVerify(certificate.getPublicKey());
        sig.update(req.getProtectedBytes());
        boolean verified = sig.verify(req.getProtection().getBytes());
        assertTrue("Signing the message failed.", verified);
        */
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null);
        X509Certificate cert = checkKurCertRepMessage(userDN, cacert, resp, reqId);
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
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "false");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "false"));
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY, "true");

        //--------------- create the user and issue his first certificate -----------------
        createUser(username, userDN, "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = null;
        try {
            certificate = (X509Certificate) signSession.createCertificate(admin, username, "foo123", keys.getPublic());
        } catch (ObjectNotFoundException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (CADoesntExistsException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (EjbcaException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (AuthorizationDeniedException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (CesecoreException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        }
        assertNotNull("Failed to create a test certificate", certificate);

        
        
        PKIMessage req = genRenewalReq(keys, false);
        assertNotNull("Failed to generate a CMP renewal request", req);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        req.getHeader().setProtectionAlg(pAlg);      
        req.getHeader().setSenderKID(new DEROctetString(nonce));
        addExtraCert(req, certificate);
        signPKIMessage(req, keys);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        final String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        final String expectedErrMsg = "Got request with status GENERATED (40), NEW, FAILED or INPROCESS required: " + username + ".";
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
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true"));
        
        //--------------- create the user and issue his first certificate -----------------
        createUser(username, userDN, "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = null;
        try {
            certificate = (X509Certificate) signSession.createCertificate(admin, username, "foo123", keys.getPublic());
        } catch (ObjectNotFoundException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (CADoesntExistsException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (EjbcaException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (AuthorizationDeniedException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (CesecoreException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        }
        assertNotNull("Failed to create a test certificate", certificate);

        certStoreSession.setRevokeStatus(admin, certificate, RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION, null);
        assertTrue("Failed to revoke the test certificate", certStoreSession.isRevoked(CertTools.getIssuerDN(certificate), CertTools.getSerialNumber(certificate)));

        
        
        PKIMessage req = genRenewalReq(keys, false);
        assertNotNull("Failed to generate a CMP renewal request", req);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        req.getHeader().setProtectionAlg(pAlg);      
        req.getHeader().setSenderKID(new DEROctetString(nonce));
        addExtraCert(req, certificate);
        signPKIMessage(req, keys);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        final String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        final String expectedErrMsg = "The certificate attached to the PKIMessage in the extraCert field is revoked.";
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
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true"));
        
        //--------------- create the user and issue his first certificate -----------------
        final String fakeUserDN = "CN=fakeuser,C=SE";
        //createUser(username, userDN, "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate fakeCert = null;
            //certificate = (X509Certificate) signSession.createCertificate(admin, username, "foo123", keys.getPublic());
        fakeCert = CertTools.genSelfCert(fakeUserDN, 30, null, keys.getPrivate(), keys.getPublic(),
                    AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        assertNotNull("Failed to create a test certificate", fakeCert);
        
        PKIMessage req = genRenewalReq(keys, false);
        assertNotNull("Failed to generate a CMP renewal request", req);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        req.getHeader().setProtectionAlg(pAlg);      
        req.getHeader().setSenderKID(new DEROctetString(nonce));
        addExtraCert(req, fakeCert);
        signPKIMessage(req, keys);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        final String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        final String expectedErrMsg = "The certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
        assertEquals(expectedErrMsg, errMsg);

        if(log.isTraceEnabled()) {
            log.trace("<test04UpdateKeyWithFakeCert");
        }

    }
    

    /**
     * Sends a KeyUpdateRequest in RA mode. A CMP error message is expected and no certificate renewal.
     * 
     * - Pre-configuration: Sets the operational mode to RA mode (cmp.raoperationalmode=ra)
     * - Pre-configuration: Sets cmp.allowautomaticrenewal to 'true' and tests that the resetting of configuration has worked.
     * - Pre-configuration: Sets cmp.allowupdatewithsamekey to 'true'
     * - Creates a new user and obtains a certificate, cert, for this user. Tests whether obtaining the certificate was successful.
     * - Generates a CMP KeyUpdate Request and tests that such request has been created.
     * - Signs the CMP request using fakecert and attaches fakecert to the CMP request. Tests that the CMP request is still not null
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
    public void test05UpdateKeyInRAMode() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test04UpdateKeyWithFakeCert");
        }
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true"));
        
        //--------------- create the user and issue his first certificate -----------------
        createUser(username, userDN, "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = null;
        certificate = (X509Certificate) signSession.createCertificate(admin, username, "foo123", keys.getPublic());
        assertNotNull("Failed to create a test certificate", certificate);

        
        
        PKIMessage req = genRenewalReq(keys, false);
        assertNotNull("Failed to generate a CMP renewal request", req);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        req.getHeader().setProtectionAlg(pAlg);      
        req.getHeader().setSenderKID(new DEROctetString(nonce));
        addExtraCert(req, certificate);
        signPKIMessage(req, keys);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        final String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        final String expectedErrMsg = "This request can only be processed in client mode";
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
    public void test07UpdateWithSameKeyNotAllowed() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test07UpdateWithSameKeyNotAllowed");
        }
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true"));
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY, "false");

        //--------------- create the user and issue his first certificate -----------------
        createUser(username, userDN, "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = null;
        certificate = (X509Certificate) signSession.createCertificate(admin, username, "foo123", keys.getPublic());
        assertNotNull("Failed to create a test certificate", certificate);

        
        
        PKIMessage req = genRenewalReq(keys, false);
        assertNotNull("Failed to generate a CMP renewal request", req);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        req.getHeader().setProtectionAlg(pAlg);      
        req.getHeader().setSenderKID(new DEROctetString(nonce));
        addExtraCert(req, certificate);
        signPKIMessage(req, keys);
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        final String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
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
    public void test08UpdateWithDifferentKey() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test08UpdateWithDifferentKey");
        }
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true"));
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY, "false");

        
        //--------------- create the user and issue his first certificate -----------------
        createUser(username, userDN, "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = null;
        certificate = (X509Certificate) signSession.createCertificate(admin, username, "foo123", keys.getPublic());
        assertNotNull("Failed to create a test certificate", certificate);

        
        KeyPair newkeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        PKIMessage req = genRenewalReq(newkeys, false);
        assertNotNull("Failed to generate a CMP renewal request", req);
        int reqId = req.getBody().getKur().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        req.getHeader().setProtectionAlg(pAlg);      
        req.getHeader().setSenderKID(new DEROctetString(nonce));
        addExtraCert(req, certificate);
        signPKIMessage(req, keys);
        assertNotNull(req);
        //******************************************''''''
        final Signature sig = Signature.getInstance(req.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
        sig.initVerify(certificate.getPublicKey());
        sig.update(req.getProtectedBytes());
        boolean verified = sig.verify(req.getProtection().getBytes());
        assertTrue("Signing the message failed.", verified);
        //***************************************************
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null);
        X509Certificate cert = checkKurCertRepMessage(userDN, cacert, resp, reqId);
        assertNotNull("Failed to renew the certificate", cert);
        assertTrue("The new certificate's keys are incorrect.", cert.getPublicKey().equals(newkeys.getPublic()));
        assertFalse("The new certificate's keys are the same as the old certificate's keys.", cert.getPublicKey().equals(keys.getPublic()));
        
        if(log.isTraceEnabled()) {
            log.trace("<test08UpdateWithDifferentKey");
        }

    }

    
    
    
    @After
    public void tearDown() throws Exception {

        super.tearDown();
        
        try {
            userAdminSession.revokeAndDeleteUser(admin, username, ReasonFlags.unused);
            userAdminSession.revokeAndDeleteUser(admin, "fakeuser", ReasonFlags.unused);

        } catch(Exception e){}
        
        boolean cleanUpOk = true;
        if (!confSession.restoreConfiguration()) {
            cleanUpOk = false;
        }
        assertTrue("Unable to clean up properly.", cleanUpOk);
    }
    
    
    private void setCAID() throws CADoesntExistsException, AuthorizationDeniedException {
        // Try to use AdminCA1 if it exists
        CAInfo adminca1 = caSession.getCAInfo(admin, "AdminCA1");

        if (adminca1 == null) {
            final Collection<Integer> caids;

            caids = caSession.getAvailableCAs(admin);
            final Iterator<Integer> iter = caids.iterator();
            int tmp = 0;
            while (iter.hasNext()) {
                tmp = iter.next().intValue();
                if(tmp != 0)    break;
            }
            caid = tmp;
        } else {
            caid = adminca1.getCAId();
        }
        if (caid == 0) {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
 
    }
    
    private void setCaCert() throws CADoesntExistsException, AuthorizationDeniedException {
        final CAInfo cainfo;

        cainfo = caSession.getCAInfo(admin, caid);

        Collection<Certificate> certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<Certificate> certiter = certs.iterator();
            Certificate cert = certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                try {
                    cacert = (X509Certificate) CertTools.getCertfromByteArray(cert.getEncoded());
                } catch (Exception e) {
                    throw new Error(e);
                }
            } else {
                cacert = null;
            }
        } else {
            log.error("NO CACERT for caid " + caid);
            cacert = null;
        }
    }
    
    private void addExtraCert(PKIMessage msg, Certificate cert) throws CertificateEncodingException, IOException{
        ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
        ASN1InputStream         dIn = new ASN1InputStream(bIn);
        ASN1Sequence extraCertSeq = (ASN1Sequence)dIn.readObject();
        X509CertificateStructure extraCert = new X509CertificateStructure(ASN1Sequence.getInstance(extraCertSeq));
        msg.addExtraCert(extraCert);
    }
    
    private void signPKIMessage(PKIMessage msg, KeyPair keys) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        final Signature sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "BC");
        sig.initSign(keys.getPrivate());
        sig.update(msg.getProtectedBytes());
        byte[] eeSignature = sig.sign();            
        msg.setProtection(new DERBitString(eeSignature));   
    }
    
    private EndEntityInformation createUser(String username, String subjectDN, String password) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, 
                WaitingForApprovalException, EjbcaException, Exception {

        EndEntityInformation user = new EndEntityInformation(username, subjectDN, caid, null, username+"@primekey.se", SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE,
        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            //userAdminSession. addUser(ADMIN, user, true);
            userAdminSession.addUser(admin, username, password, subjectDN, "rfc822name=" + username + "@primekey.se", username + "@primekey.se",
                    true, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0,
                    caid);
            log.debug("created user: " + username);
        } catch (Exception e) {
            log.debug("User " + username + " already exists. Setting the user status to NEW");
            userAdminSession.changeUser(admin, user, true);
            userAdminSession.setUserStatus(admin, username, UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }

        return user;

    }
    
    private PKIMessage genRenewalReq(KeyPair keys, boolean raVerifiedPopo) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, 
                        InvalidKeyException, SignatureException {
        
        CertTemplate myCertTemplate = new CertTemplate();
        
        OptionalValidity myOptionalValidity = new OptionalValidity();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date());
        myOptionalValidity.setNotBefore(nb);
        myOptionalValidity.setNotAfter(na);
        myCertTemplate.setValidity(myOptionalValidity);
        
        byte[] bytes = keys.getPublic().getEncoded();
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream dIn = new ASN1InputStream(bIn);
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());
        myCertTemplate.setPublicKey(keyInfo);

        CertRequest myCertRequest = new CertRequest(new DERInteger(4), myCertTemplate);
        // myCertRequest.addControls(new
        // AttributeTypeAndValue(CRMFObjectIdentifiers.regInfo_utf8Pairs, new
        // DERInteger(12345)));
        CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest);

        // POPO
        /*
         * PKMACValue myPKMACValue = new PKMACValue( new AlgorithmIdentifier(new
         * DERObjectIdentifier("8.2.1.2.3.4"), new DERBitString(new byte[] { 8,
         * 1, 1, 2 })), new DERBitString(new byte[] { 12, 29, 37, 43 }));
         * 
         * POPOPrivKey myPOPOPrivKey = new POPOPrivKey(new DERBitString(new
         * byte[] { 44 }), 2); //take choice pos tag 2
         * 
         * POPOSigningKeyInput myPOPOSigningKeyInput = new POPOSigningKeyInput(
         * myPKMACValue, new SubjectPublicKeyInfo( new AlgorithmIdentifier(new
         * DERObjectIdentifier("9.3.3.9.2.2"), new DERBitString(new byte[] { 2,
         * 9, 7, 3 })), new byte[] { 7, 7, 7, 4, 5, 6, 7, 7, 7 }));
         */
        ProofOfPossession myProofOfPossession = null;
        if (raVerifiedPopo) {
            // raVerified POPO (meaning there is no POPO)
            myProofOfPossession = new ProofOfPossession(new DERNull(), 0);
        } else {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DEROutputStream mout = new DEROutputStream(baos);
            mout.writeObject(myCertRequest);
            mout.close();
            byte[] popoProtectionBytes = baos.toByteArray();
            Signature sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "BC");
            sig.initSign(keys.getPrivate());
            sig.update(popoProtectionBytes);

            DERBitString bs = new DERBitString(sig.sign());

            POPOSigningKey myPOPOSigningKey = new POPOSigningKey(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption), bs);
            // myPOPOSigningKey.setPoposkInput( myPOPOSigningKeyInput );
            myProofOfPossession = new ProofOfPossession(myPOPOSigningKey, 1);
        }

        myCertReqMsg.setPop(myProofOfPossession);
        // myCertReqMsg.addRegInfo(new AttributeTypeAndValue(new
        // DERObjectIdentifier("1.3.6.2.2.2.2.3.1"), new
        // DERInteger(1122334455)));
        AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.regCtrl_regToken, new DERUTF8String("foo123"));
        myCertReqMsg.addRegInfo(av);

        CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);
        // myCertReqMessages.addCertReqMsg(myCertReqMsg);

        // log.debug("CAcert subject name: "+cacert.getSubjectDN().getName());
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(userDN)), new GeneralName(new X509Name(
                ((X509Certificate) cacert).getSubjectDN().getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
        // myPKIHeader.setRecipNonce(new DEROctetString(new
        // String("RecipNonce").getBytes()));
        // PKIFreeText myPKIFreeText = new PKIFreeText(new
        // DERUTF8String("hello"));
        // myPKIFreeText.addString(new DERUTF8String("free text string"));
        // myPKIHeader.setFreeText(myPKIFreeText);

        PKIBody myPKIBody = new PKIBody(myCertReqMessages, 7); // Key Update Request
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
        
        return myPKIMessage;

    }
    

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    private X509Certificate checkKurCertRepMessage(String userDN, Certificate cacert, byte[] retMsg, int requestId) throws IOException,
                        CertificateException {
        //
        // Parse response message
        //
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        int tag = body.getTagNo();
        assertEquals(8, tag);
        CertRepMessage c = body.getKup();
        assertNotNull(c);
        CertResponse resp = c.getResponse(0);
        assertNotNull(resp);
        assertEquals(resp.getCertReqId().getValue().intValue(), requestId);
        PKIStatusInfo info = resp.getStatus();
        assertNotNull(info);
        assertEquals(0, info.getStatus().getValue().intValue());
        CertifiedKeyPair kp = resp.getCertifiedKeyPair();
        assertNotNull(kp);
        CertOrEncCert cc = kp.getCertOrEncCert();
        assertNotNull(cc);
        X509CertificateStructure struct = cc.getCertificate();
        assertNotNull(struct);
        checkDN(userDN, struct.getSubject());
        assertEquals(CertTools.stringToBCDNString(struct.getIssuer().toString()), CertTools.getSubjectDN(cacert));
        return (X509Certificate) CertTools.getCertfromByteArray(struct.getEncoded());
    }

}
