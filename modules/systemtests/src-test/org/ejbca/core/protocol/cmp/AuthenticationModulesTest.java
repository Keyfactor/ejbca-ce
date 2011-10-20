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
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.ejb.CreateException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.RemoveException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSession;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.CertificateCreationException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfigurationHolder;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.cmp.authentication.HMACAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.VerifyPKIMessage;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * This will test the different cmp authentication modules.
 * 
 * @version $Id$
 *
 */
public class AuthenticationModulesTest extends CmpTestCase {

    
    private static final Logger log = Logger.getLogger(AuthenticationModulesTest.class);

    private static final AuthenticationToken ADMIN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AuthenticationModulesTest"));
    
    private String username;
    private String userDN;
    private String issuerDN;
    private byte[] nonce;
    private byte[] transid;
    private int caid;
    private Certificate cacert;
    
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private EndEntityAccessSessionRemote eeAccessSession = InterfaceCache.getEndEntityAccessSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private EndEntityProfileSession eeProfileSession = InterfaceCache.getEndEntityProfileSession();
    //private CertificateProfileSession certProfSession = InterfaceCache.getCertificateProfileSession();
    private ConfigurationSessionRemote confSession = JndiHelper.getRemoteSession(ConfigurationSessionRemote.class); //InterfaceCache.getConfigurationSession();
    private CertificateStoreSession certStoreSession = InterfaceCache.getCertificateStoreSession();
    private AccessControlSession authorizationSession = InterfaceCache.getAccessControlSession();
    //private RoleInitializationSessionRemote roleInitSession = JndiHelper.getRemoteSession(RoleInitializationSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSessionRemote = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    
//    @EJB
//    private WebAuthenticationProviderSessionLocal authenticationProviderSession = null;
    
    
    @Before
    public void setUp() throws Exception {
        super.setUp();

        username = "authModuleTestUser";
        userDN = "CN="+username+",O=PrimeKey Solutions AB,C=SE,UID=foo123";
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
        
        confSession.backupConfiguration();
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");

    }
    
    @Test
    public void test01HMACModule() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, InvalidAlgorithmParameterException, CADoesntExistsException, AuthorizationDeniedException {
        
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        assertFalse("caid is 0", (caid==0));
        assertNotNull("cacert is null", cacert);
        PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null); 
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

        HMACAuthenticationModule hmac = new HMACAuthenticationModule("foo123");
        hmac.setCaInfo(caSession.getCAInfo(ADMIN, caid));
        hmac.setSession(ADMIN, eeAccessSession, certStoreSession);
        boolean res = hmac.verifyOrExtract(req);
        assertTrue("Verifying the message authenticity using HMAC failed.", res);
        assertNotNull("HMAC returned null password.", hmac.getAuthenticationString());
        assertEquals("HMAC returned the wrong password", "foo123", hmac.getAuthenticationString());

    }

    @Test
    public void test02HMACCrmfReq() throws Exception {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123"));      
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
        
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert1 = checkCmpCertRepMessage(userDN, cacert, resp, req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
    }
    
    @Test
    public void test03HMACRevReq() throws Exception {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123"));      
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
        
        Collection<Certificate> certs = certStoreSession.findCertificatesBySubjectAndIssuer(userDN, issuerDN);
        log.debug("Found " + certs.size() + " certificates for userDN \"" + userDN + "\"");
        Certificate cert = null, tmp=null;
        Iterator<Certificate> itr = certs.iterator();
        while(itr.hasNext()) {
            tmp = itr.next();
            if(!certStoreSession.isRevoked(issuerDN, CertTools.getSerialNumber(tmp))) {
                cert = tmp;
                break;
            }
        }
        if(cert == null) {
            createUser("cmprevuser1", "CN=cmprevuser1,C=SE", "foo123");
            KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
            cert = signSession.createCertificate(ADMIN, "cmpTestAdmin", "foo123", admkeys.getPublic());
        }
        assertNotNull("No certificate to revoke.", cert);
        
        
        PKIMessage msg = genRevReq(issuerDN, userDN, CertTools.getSerialNumber(cert), cacert, nonce, transid, false);
        assertNotNull("Generating RevocationRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, null);
        int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
        assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
    }
    
    @Test
    public void test04EECrmfReq() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception  {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null); 
        assertNotNull("Generating CrmfRequest failed.", msg);
        
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        msg.getHeader().setProtectionAlg(pAlg);      
        msg.getHeader().setSenderKID(new DEROctetString(nonce));

        String adminName = "cmpTestAdmin";
        //createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken admToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE");
        Certificate admCert = getCertFromCredentials(admToken);
        addExtraCert(msg, admCert);
        signPKIMessage(msg, admkeys);
        assertNotNull(msg);
        //******************************************''''''
        final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
        sig.initVerify(admCert.getPublicKey());
        sig.update(msg.getProtectedBytes());
        boolean verified = sig.verify(msg.getProtection().getBytes());
        assertTrue("Signing the message failed.", verified);
        //***************************************************
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert2 = checkCmpCertRepMessage(userDN, cacert, resp, msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("CrmfRequest did not return a certificate", cert2);
        
        removeAuthenticationToken(admToken, admCert, adminName);
    }
    
    @Test
    public void test05EERevReq() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception  {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        Collection<Certificate> certs = certStoreSession.findCertificatesBySubjectAndIssuer(userDN, issuerDN);
        log.debug("Found " + certs.size() + " certificates for userDN \"" + userDN + "\"");
        Certificate cert = null, tmp=null;
        Iterator<Certificate> itr = certs.iterator();
        while(itr.hasNext()) {
            tmp = itr.next();
            if(!certStoreSession.isRevoked(issuerDN, CertTools.getSerialNumber(tmp))) {
                cert = tmp;
                break;
            }
        }
        if(cert == null) {
            createUser("cmprevuser1", "CN=cmprevuser1,C=SE", "foo123");
            KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
            cert = signSession.createCertificate(ADMIN, "cmpTestAdmin", "foo123", admkeys.getPublic());
        }
        assertNotNull("No certificate to revoke.", cert);
        
        PKIMessage msg = genRevReq(issuerDN, userDN, CertTools.getSerialNumber(cert), cacert, nonce, transid, false);   
        assertNotNull("Generating CrmfRequest failed.", msg);
        
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        msg.getHeader().setProtectionAlg(pAlg);      
        msg.getHeader().setSenderKID(new DEROctetString(nonce));

        String adminName = "cmpTestAdmin";
        //createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE");
        Certificate admCert = getCertFromCredentials(adminToken);
        addExtraCert(msg, admCert);
        signPKIMessage(msg, admkeys);
        assertNotNull(msg);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);
        int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
        assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
        
        removeAuthenticationToken(adminToken, admCert, adminName);
    }
    
    @Test
    public void test06EECrmfReqMultipleAuthModules() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception  {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        String modules = CmpConfiguration.AUTHMODULE_HMAC + ";" + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
        String parameters = "foo123" + ";" + "AdminCA1";
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

     
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null); 
        assertNotNull("Generating CrmfRequest failed.", msg);
        
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        msg.getHeader().setProtectionAlg(pAlg);      
        msg.getHeader().setSenderKID(new DEROctetString(nonce));

        String adminName = "cmpTestAdmin";
        //createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE");
        Certificate admCert = getCertFromCredentials(adminToken);
        addExtraCert(msg, admCert);
        signPKIMessage(msg, admkeys);
        assertNotNull(msg);
        
        
        
/*
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null); 
        assertNotNull("Generating CrmfRequest failed.", msg);
        
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        msg.getHeader().setProtectionAlg(pAlg);      
        msg.getHeader().setSenderKID(new DEROctetString(nonce));
        
        String adminName = "cmpTestAdmin";
        //createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(keys, adminName, "CN=" + adminName + ",C=SE");
        Certificate admCert = getCertFromCredentials(adminToken);
        addExtraCert(msg, admCert);
        signPKIMessage(msg, admkeys);
        assertNotNull(msg);
*/        
        //********************************************
        final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
        sig.initVerify(admCert.getPublicKey());
        sig.update(msg.getProtectedBytes());
        boolean verified = sig.verify(msg.getProtection().getBytes());
        assertTrue("Signing the message failed.", verified);
        //********************************************
        
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert2 = checkCmpCertRepMessage(userDN, cacert, resp, msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("CrmfRequest did not return a certificate", cert2);
        
        removeAuthenticationToken(adminToken, admCert, adminName);
    }
    
    @Test
    public void test07HMACCrmfReqMultipleAuthenticationModules() throws Exception {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        String modules = CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + ";" + CmpConfiguration.AUTHMODULE_HMAC;
        String parameters = "-;AdminCA1;foo123hmac";
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules);
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters);
        
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
        
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123hmac", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert1 = checkCmpCertRepMessage(userDN, cacert, resp, req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
        
        VerifyPKIMessage verifier = new VerifyPKIMessage(caSession.getCAInfo(ADMIN, caid), ADMIN, caSession, eeAccessSession, certStoreSession, authorizationSession, eeProfileSession, null);
        boolean verify = verifier.verify(req);
        assertTrue("Verifying PKIMessage failed", verify);
        assertEquals(CmpConfiguration.AUTHMODULE_HMAC, verifier.getUsedAuthenticationModule().getName());
    }
    
    @Test
    public void test08HMACCrmfReqWrongAuthenticationModule() throws Exception {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());

        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_DN_PART_PWD);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_DN_PART_PWD));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "UID");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "UID"));     
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());


        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123hmac", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);   
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, null);
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        String expectedErrMsg = "Unrecognized authentication module '" + CmpConfiguration.AUTHMODULE_DN_PART_PWD + "'";
        assertEquals(expectedErrMsg, errMsg);
    }
    
    @Test
    public void test09EECrmfCheckAdminAuthorization() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception  {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null); 
        assertNotNull("Generating CrmfRequest failed.", msg);
        
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        msg.getHeader().setProtectionAlg(pAlg);      
        msg.getHeader().setSenderKID(new DEROctetString(nonce));

        String adminName ="cmpTestUnauthorizedAdmin"; 
        createUser(adminName , "CN=" + adminName + ",C=SE", "foo123");
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        Certificate admCert = signSession.createCertificate(ADMIN, adminName, "foo123", admkeys.getPublic());
        addExtraCert(msg, admCert);
        signPKIMessage(msg, admkeys);
        assertNotNull(msg);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);

        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        assertEquals("\"CN=cmpTestUnauthorizedAdmin,C=SE\" is not an authorized administrator.", errMsg);
        
        confSession.updateProperty(CmpConfiguration.CONFIG_CHECKADMINAUTHORIZATION, "false");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_CHECKADMINAUTHORIZATION, "false"));
        
        final byte[] resp2 = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp2, issuerDN, userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert2 = checkCmpCertRepMessage(userDN, cacert, resp2, msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("CrmfRequest did not return a certificate", cert2);
    }
    
    @Test
    public void test10CrmfReqClientModeHMAC() throws Exception {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());

        String clientPassword = "foo123client";

        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, clientPassword);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, clientPassword));        
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
        confSession.updateProperty(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        
        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        //try{
        //    userAdminSession.revokeAndDeleteUser(ADMIN, clientUsername, ReasonFlags.unused);
        //} catch(Exception e) {}
        createUser(clientUsername, clientDN, clientPassword);
        
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, true, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        X509Name reqissuer = msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertTemplate().getIssuer();
        assertNotNull("reqissuer is null", reqissuer);

        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);

        // 
        // Try a request with no issuerDN in the certTemplate
        createUser(clientUsername, clientDN, clientPassword);
        PKIMessage msgNoIssuer = genCertReq(null, clientDN, keys, cacert, nonce, transid, true, null, null, null, null);
        assertNotNull("Generating CrmfRequest with no issuer failed.", msgNoIssuer);
        PKIMessage reqNoIssuer = protectPKIMessage(msgNoIssuer, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        ByteArrayOutputStream bao2 = new ByteArrayOutputStream();
        DEROutputStream out2 = new DEROutputStream(bao2);
        out2.writeObject(reqNoIssuer);
        byte[] ba2 = bao2.toByteArray();
        // Send request and receive response
        byte[] respNoIssuer = sendCmpHttp(ba2, 200);        
        checkCmpResponseGeneral(respNoIssuer, issuerDN, clientDN, cacert, reqNoIssuer.getHeader().getSenderNonce().getOctets(), reqNoIssuer.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert2 = checkCmpCertRepMessage(clientDN, cacert, respNoIssuer, reqNoIssuer.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert2);

        // Send a confirm message to the CA
        String hash = CertTools.getFingerprintAsString(cert2);
        int reqId = reqNoIssuer.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        ByteArrayOutputStream bao3 = new ByteArrayOutputStream();
        DEROutputStream out3 = new DEROutputStream(bao3);
        out3.writeObject(confirm);
        byte[] ba3 = bao3.toByteArray();
        // Send request and receive response
        byte[] resp3 = sendCmpHttp(ba3, 200);
        checkCmpResponseGeneral(resp3, issuerDN, userDN, cacert, nonce, transid, false, null);
        checkCmpPKIConfirmMessage(userDN, cacert, resp3);

    }
    
    @Test
    public void test11HMACModuleInClientMode() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, 
                        InvalidAlgorithmParameterException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, 
                        EjbcaException, java.lang.Exception {
        
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
        
        
        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        String clientPassword = "foo123client";
        try {
            userAdminSession.revokeAndDeleteUser(ADMIN, clientUsername, ReasonFlags.unused);
        } catch(Exception e) {}
        createUser(clientUsername, clientDN, clientPassword);
        
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);   
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage failed", req);

        HMACAuthenticationModule hmac = new HMACAuthenticationModule("foo123");
        hmac.setCaInfo(caSession.getCAInfo(ADMIN, caid));
        hmac.setSession(ADMIN, eeAccessSession, certStoreSession);
        boolean res = hmac.verifyOrExtract(req);
        assertTrue("Verifying the message authenticity using HMAC failed.", res);
        assertNotNull("HMAC returned null password.", hmac.getAuthenticationString());
        assertEquals("HMAC returned the wrong password", clientPassword, hmac.getAuthenticationString());

        // Test the same but without issuerDN in the request
        msg = genCertReq(null, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage failed", req);
        res = hmac.verifyOrExtract(req);
        assertTrue("Verifying the message authenticity using HMAC failed.", res);
        assertNotNull("HMAC returned null password.", hmac.getAuthenticationString());
        assertEquals("HMAC returned the wrong password", clientPassword, hmac.getAuthenticationString());
    }
    
    @Test
    public void test12CrmfReqClientModeRegToken() throws Exception {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-"));       
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
        
        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        String clientPassword = "foo123client";
        try{
            userAdminSession.revokeAndDeleteUser(ADMIN, clientUsername, ReasonFlags.unused);
        } catch(Exception e) {}
        createUser(clientUsername, clientDN, "foo123");
        
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
    }
    
    @Test
    public void test13CrmfReqClientModeMultipleModules() throws Exception {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        String authmodules = CmpConfiguration.AUTHMODULE_HMAC + ";" + CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD;
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, authmodules);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, authmodules));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, authmodules);
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123hmac;-");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123hmac;-"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123;-");

        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
        
        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        //String clientPassword = "foo123client";
        try{
            userAdminSession.revokeAndDeleteUser(ADMIN, clientUsername, ReasonFlags.unused);
        } catch(Exception e) {}
        createUser(clientUsername, clientDN, "foo123");
        
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
        
        VerifyPKIMessage verifier = new VerifyPKIMessage(caSession.getCAInfo(ADMIN, caid), ADMIN, caSession, eeAccessSession, certStoreSession, authorizationSession, eeProfileSession, null);
        boolean verify = verifier.verify(msg);
        assertTrue(verify);
        assertEquals(CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD, verifier.getUsedAuthenticationModule().getName());
    }
    
    @Test
    public void test14HMACCrmfReqClientModeHMACInvalidPassword() throws Exception {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123client");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123client"));        
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
        
        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        String clientPassword = "foo123client";
        try{
            userAdminSession.revokeAndDeleteUser(ADMIN, clientUsername, ReasonFlags.unused);
        } catch(Exception e) {}
        createUser(clientUsername, clientDN, "foo123ee");
        
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, null);
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        String expectedErrMsg = "Authentication failed for message. clientTestUser.";
        assertEquals(expectedErrMsg, errMsg);
    }
    
    public void test15HMACCrmfReqClientModeHMACInvalidPassword() throws Exception {
        assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123client");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123client"));        
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
        
        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        String clientPassword = "foo123client";
        try{
            userAdminSession.revokeAndDeleteUser(ADMIN, clientUsername, ReasonFlags.unused);
        } catch(Exception e) {}
        createUser(clientUsername, clientDN, "foo123ee");
        
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, null);
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        String expectedErrMsg = "Authentication failed for message. clientTestUser.";
        assertEquals(expectedErrMsg, errMsg);
    }

    @Test
    public void test99RestoreConf() {
        assertTrue("Restoring configuration faild.", confSession.restoreConfiguration());
        try {
            userAdminSession.revokeAndDeleteUser(ADMIN, username, ReasonFlags.unused);
            userAdminSession.revokeAndDeleteUser(ADMIN, "cmpTestUnauthorizedAdmin", ReasonFlags.keyCompromise);
        } catch(Exception e){}
        
    }
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        
        boolean cleanUpOk = true;
        if (!confSession.restoreConfiguration()) {
            cleanUpOk = false;
        }
        assertTrue("Unable to clean up properly.", cleanUpOk);
    }
    
    
    
    
    
    
    
    
    
    
    private void setCAID() throws CADoesntExistsException, AuthorizationDeniedException {
        // Try to use AdminCA1 if it exists
        CAInfo adminca1 = caSession.getCAInfo(ADMIN, "AdminCA1");

        if (adminca1 == null) {
            final Collection<Integer> caids;

            caids = caSession.getAvailableCAs(ADMIN);
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
 
        /*
        if (adminca1 == null) {
            Collection<Integer> caids = caSession.getAvailableCAs(ADMIN);
            Iterator<Integer> iter = caids.iterator();
            while (iter.hasNext()) {
                caid = iter.next().intValue();
            }
        } else {
            caid = adminca1.getCAId();
        }
        if (caid == 0) {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        */
    }
    
    private void setCaCert() throws CADoesntExistsException, AuthorizationDeniedException {
        final CAInfo cainfo;

        cainfo = caSession.getCAInfo(ADMIN, caid);

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
        SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            //userAdminSession. addUser(ADMIN, user, true);
            userAdminSession.addUser(ADMIN, username, password, subjectDN, "rfc822name=" + username + "@primekey.se", username + "@primekey.se",
                    true, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0,
                    caid);
            log.debug("created user: " + username);
        } catch (Exception e) {
            log.debug("User " + username + " already exists. Setting the user status to NEW");
            userAdminSession.changeUser(ADMIN, user, true);
            userAdminSession.setUserStatus(ADMIN, username, UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }

        return user;

    }
    
    private X509Certificate getCertFromCredentials(AuthenticationToken authToken) {
        X509Certificate certificate = null;
        Set<?> inputcreds = authToken.getCredentials();
        if (inputcreds != null) {
            for (Object object : inputcreds) {
                if (object instanceof X509Certificate) {
                    certificate = (X509Certificate) object;
                }
            }           
        }
        return certificate;
    }
    
    private AuthenticationToken createAdminToken(KeyPair keys, String name, String dn) throws RoleExistsException, RoleNotFoundException, CreateException, AuthorizationDeniedException {
        Set<Principal> principals = new HashSet<Principal>();
        X500Principal p = new X500Principal(dn);
        principals.add(p);
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        AuthenticationToken token = createTokenWithCert(name, subject, keys);
        X509Certificate cert = (X509Certificate) token.getCredentials().iterator().next();

        // Initialize the role mgmt system with this role that is allowed to edit roles

        String roleName = "Super Administrator Role";
        RoleData roledata = roleAccessSessionRemote.findRole(roleName); 
        // Create a user aspect that matches the authentication token, and add that to the role.
        List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
        accessUsers.add(new AccessUserAspectData(roleName, CertTools.getIssuerDN(cert).hashCode(), X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                    AccessMatchType.TYPE_EQUALCASEINS, CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN")));
        roleManagementSession.addSubjectsToRole(ADMIN, roledata, accessUsers);

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
        
        X509Certificate certificate = null;
        // If we have a certificate as input, use that, otherwise generate a self signed certificate
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        
        // If there was no certificate input, create a self signed
            String dn = "C=SE,O=Test,CN=Test"; // default
            // If we have created a subject with an X500Principal we will use this DN to create the dummy certificate.
            if (subject != null) {
                Set<Principal> principals = subject.getPrincipals();
                if ((principals != null) && (principals.size() > 0)) {
                    Principal p = principals.iterator().next();
                    if (p instanceof X500Principal) {
                        X500Principal xp = (X500Principal)p;
                        dn = xp.getName();
                    }
                }
            }
            
            try {
                createUser(adminName, dn, "foo123");
            } catch (AuthorizationDeniedException e1) {
                throw new CertificateCreationException("Error encountered when creating admin user", e1);
            } catch (UserDoesntFullfillEndEntityProfile e1) {
                throw new CertificateCreationException("Error encountered when creating admin user", e1);
            } catch (WaitingForApprovalException e1) {
                throw new CertificateCreationException("Error encountered when creating admin user", e1);
            } catch (EjbcaException e1) {
                throw new CertificateCreationException("Error encountered when creating admin user", e1);
            } catch (Exception e1) {
                throw new CertificateCreationException("Error encountered when creating admin user", e1);
            }
            
            try {
                certificate = (X509Certificate) signSession.createCertificate(ADMIN, adminName, "foo123", keys.getPublic());
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

            
        // Add the credentials and new principal
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());

        // We cannot use the X509CertificateAuthenticationToken here, since it can only be used internally in a JVM.
        AuthenticationToken result = new TestX509CertificateAuthenticationToken(principals, credentials);
        return result;
    }
    
    private void removeAuthenticationToken(AuthenticationToken authToken, Certificate cert, String adminName) throws RoleNotFoundException, AuthorizationDeniedException, ApprovalException, NotFoundException, WaitingForApprovalException, RemoveException {
        String rolename = "Super Administrator Role";
        
        RoleData roledata = roleAccessSessionRemote.findRole("Super Administrator Role");
        if (roledata != null) {            

            //Set<X509Certificate> credentials = (Set<X509Certificate>) authToken.getCredentials();
            //Certificate cert = credentials.iterator().next();

            List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
            accessUsers.add(new AccessUserAspectData(rolename, CertTools.getIssuerDN(cert).hashCode(), X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                    AccessMatchType.TYPE_EQUALCASEINS, CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN")));
            
            roleManagementSession.removeSubjectsFromRole(ADMIN, roledata, accessUsers);
        }
        
        userAdminSession.revokeAndDeleteUser(ADMIN, adminName, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);        
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    

}
