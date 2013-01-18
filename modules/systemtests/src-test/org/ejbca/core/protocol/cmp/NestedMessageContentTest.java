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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.ejb.CreateException;
import javax.ejb.RemoveException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.CertificateCreationException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfigurationHolder;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.hibernate.ObjectNotFoundException;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;

/**
 * This will the the different kind of CMP messages that can be sent as NestedMessageContent and if 
 * they are verified correctly
 * 
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class NestedMessageContentTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(NestedMessageContentTest.class);
    
    final private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("NestedMessageContentTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private CertificateProfileSession certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSession eeProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CertificateStoreSession certSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private int caid;
    private Certificate cacert;
    private String subjectDN;
    private String issuerDN;
    private String raCertsPath = "/tmp/racerts";
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
        
        CryptoProviderTools.installBCProvider();

        // Create a temporary directory to store ra certificates, use JUnits TemporaryFolder that is deleted on exit
        File createdFolder = folder.newFolder("racerts");
        raCertsPath = createdFolder.getCanonicalPath();
        
        subjectDN = "CN=nestedCMPTest,C=SE";
        // Configure CMP for this test, we allow custom certificate serial numbers
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setAllowValidityOverride(true);
        profile.saveData();
        try {
            certProfileSession.addCertificateProfile(admin, "CMPTESTPROFILE", profile);
        } catch (CertificateProfileExistsException e) {
            log.error("Could not create certificate profile.", e);
        }
        int cpId = certProfileSession.getCertificateProfileId("CMPTESTPROFILE");
        EndEntityProfile eep = new EndEntityProfile(true);
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE,0, "" + cpId);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES,0, "" + cpId);
        eep.addField(DnComponents.COMMONNAME);
        eep.addField(DnComponents.ORGANIZATION);
        eep.addField(DnComponents.COUNTRY);
        eep.addField(DnComponents.RFC822NAME);
        eep.addField(DnComponents.UPN);
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false);  // Don't use field from "email" data
        try {
            eeProfileSession.addEndEntityProfile(admin, "CMPTESTPROFILE", eep);
        } catch (EndEntityProfileExistsException e) {
            log.error("Could not create end entity profile.", e);
        }
        // Configure CMP for this test
        configurationSession.backupConfiguration();
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "CMPTESTPROFILE");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "CMPTESTPROFILE");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS, "CN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACERT_PATH, raCertsPath);
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1;foo123");
        // Also update raCerts path locally to be able to verify locally
        EjbcaConfigurationHolder.instance().setProperty(CmpConfiguration.CONFIG_RACERT_PATH, raCertsPath);
        
        //Set the caid and cacert
        // Try to use AdminCA1 if it exists
        final CAInfo adminca1;

        adminca1 = caSession.getCAInfo(admin, "AdminCA1");

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
        
        issuerDN = cacert != null ? ((X509Certificate) cacert).getIssuerDN().getName() : "CN=AdminCA1,O=EJBCA Sample,C=SE";
        
    }

    @Test
    public void test01CrmfReq() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
        
        //-----------------Creating CRMF request
        //PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage crmfMsg = genCertReq(issuerDN, subjectDN, keys, cacert, senderNonce, transactionID, false, null, nb.getDate(), na.getDate(), null, pAlg, new DEROctetString(senderNonce));

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE");
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate cmpcert = getCMPCert(admCert);
        crmfMsg = CmpMessageHelper.buildCertBasedPKIProtection(crmfMsg, cmpcert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(crmfMsg);
        CertReqMessages ir = (CertReqMessages) crmfMsg.getBody().getContent();
        int reqID = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        
        
        //------------------Creating NestedMessageContent
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(reqSubjectDN)), 
                    new GeneralName(new X500Name(((X509Certificate)cacert).getSubjectDN().getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));

        
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( crmfMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody myPKIBody = new PKIBody(20, seq); // NestedMessageContent
        assertNotNull("Failed to create nested Message PKIBody", myPKIBody);
        
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        assertNotNull("Failed to created nested message PKIMessage", myPKIMessage);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raCrmfSigner", "foo123", raKeys, null, null);
        myPKIMessage = CmpMessageHelper.buildCertBasedPKIProtection(myPKIMessage, null, raKeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        
        // do not check signing if we expect a failure (sFailMessage==null)
        checkCmpResponseGeneral(resp, issuerDN, subjectDN, cacert, crmfMsg.getHeader().getSenderNonce().getOctets(), crmfMsg.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert = checkCmpCertRepMessage(subjectDN, cacert, resp, reqID);
        assertNotNull("CrmfRequest did not return a certificate", cert);
        
        removeAuthenticationToken(adminToken, admCert, adminName);
    }
    
    @Test
    public void test02Verify() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
        
        //------------------- Creating Certificate Request ---------------
        //PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = null;
        keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage crmfMsg = genCertReq(issuerDN, subjectDN, keys, cacert, senderNonce, transactionID, false, null, 
                nb.getDate(), na.getDate(), null, null, null);
        assertNotNull("Failed to create crmfMsg.", crmfMsg);
        
        
        // ---------------- Creating the NestedMessageContent ----------------------
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(reqSubjectDN)), new GeneralName(new X500Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
        //myPKIHeader.addGeneralInfo(new InfoTypeAndValue(ASN1Sequence.getInstance(crmfMsg)));

        PKIBody myPKIBody = new PKIBody(20, crmfMsg); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raSignerVerify", "foo123", raKeys, null, null);
        myPKIMessage = CmpMessageHelper.buildCertBasedPKIProtection(myPKIMessage, null, raKeys.getPrivate(), null, "BC");
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);
            
        NestedMessageContent nestedMsg = new NestedMessageContent(myPKIMessage);
        boolean verify = nestedMsg.verify();
        assertTrue("NestedMessageVerification failed.", verify);
        
    }
    
    @Test
    public void test03RevReq() throws NoSuchAlgorithmException, AuthorizationDeniedException, EjbcaException, CertificateEncodingException, IOException, Exception{
        Collection<Certificate> certs = certSession.findCertificatesBySubjectAndIssuer(subjectDN, issuerDN);
        log.debug("Found " + certs.size() + " certificates for userDN \"" + subjectDN + "\"");
        Certificate cert = null, tmp=null;
        Iterator<Certificate> itr = certs.iterator();
        while(itr.hasNext()) {
            tmp = itr.next();
            if(!certSession.isRevoked(issuerDN, CertTools.getSerialNumber(tmp))) {
                cert = tmp;
                break;
            }
        }
        assertNotNull("Could not find a suitable certificate to revoke.", cert);
    
        //----------- creating the revocation signed request-------------------
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage revMsg = genRevReq(issuerDN, subjectDN, CertTools.getSerialNumber(cert), cacert, nonce, transid, false, pAlg, new DEROctetString(nonce)); 
        assertNotNull("Generating CrmfRequest failed." + revMsg);

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE");
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate cmpcert = getCMPCert(admCert);
        revMsg = CmpMessageHelper.buildCertBasedPKIProtection(revMsg, cmpcert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(revMsg);
        
        
        //----------------- Creating the nested PKIMessage -----------------------
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] reqNonce = CmpMessageHelper.createSenderNonce();
        final byte[] reqTransid = CmpMessageHelper.createSenderNonce();
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(reqSubjectDN)), new GeneralName(new X500Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(reqNonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(reqTransid));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( revMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody myPKIBody = new PKIBody(20, seq); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raRevSigner", "foo123", raKeys, null, null);
        myPKIMessage = CmpMessageHelper.buildCertBasedPKIProtection(myPKIMessage, null, raKeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, subjectDN, cacert, nonce, transid, false, null);
        int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
        assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
        
        removeAuthenticationToken(adminToken, admCert, adminName);
    }

    @Test
    public void test04CrmfRACertExist() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
        
        //------------------- Creating Certificate Request ---------------
        //PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = null;
        keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage crmfReqMsg = genCertReq(issuerDN, subjectDN, keys, cacert, senderNonce, transactionID, false, null, 
                nb.getDate(), na.getDate(), null, null, null);
        assertNotNull("Failed to create crmfMsg.", crmfReqMsg);
        PKIMessage crmfMsg = protectPKIMessage(crmfReqMsg, false, "foo123", 567);
        CertReqMessages ir = (CertReqMessages) crmfMsg.getBody().getContent();
        int reqID = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        
        
        // ---------------- Creating the NestedMessageContent ----------------------
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(reqSubjectDN)), new GeneralName(new X500Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( crmfMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody myPKIBody = new PKIBody(20, seq); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raSignerTest04", "foo123", raKeys, null, null);
        myPKIMessage = CmpMessageHelper.buildCertBasedPKIProtection(myPKIMessage, null, raKeys.getPrivate(), null, "BC");
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        //final byte[] resp = sendCmpHttp(myPKIMessage.toASN1Primitive().toASN1Object().getEncoded(), 200);
        // do not check signing if we expect a failure (sFailMessage==null)
        checkCmpResponseGeneral(resp, issuerDN, reqSubjectDN, cacert, crmfMsg.getHeader().getSenderNonce().getOctets(), crmfMsg.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert = checkCmpCertRepMessage(subjectDN, cacert, resp, reqID);
        assertNotNull("CrmfRequest did not return a certificate", cert);
        
        NestedMessageContent nestedContent = new NestedMessageContent(myPKIMessage);
        boolean ret = nestedContent.verify();
        assertTrue("The message verification failed, yet the a certificate was returned.", ret);
        
    }

    @Test
    public void test05CrmfRACertDoesNotExist() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {

        
        //------------------- Creating Certificate Request ---------------
        //PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = null;
        keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage crmfMsg = genCertReq(issuerDN, subjectDN, keys, cacert, senderNonce, transactionID, false, null, 
                nb.getDate(), na.getDate(), null, null, null);
        assertNotNull("Failed to create crmfMsg.", crmfMsg);        
        
        
        
        // ---------------- Creating the NestedMessageContent ----------------------
        
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(reqSubjectDN)), new GeneralName(new X500Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // nonce
        DEROctetString dernonce = new DEROctetString(nonce);
        myPKIHeader.setSenderNonce(dernonce);
        myPKIHeader.setRecipNonce(dernonce);
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));

        PKIBody myPKIBody = new PKIBody(20, crmfMsg); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        // Don't create a certificate, so there is no RA cert authorized on the server side.
        myPKIMessage = CmpMessageHelper.buildCertBasedPKIProtection(myPKIMessage, null, raKeys.getPrivate(), null, "BC");
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);

        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        assertEquals("Wrong error message", "Could not verify the RA, signature verification on NestedMessageContent failed.", errMsg);
        
        NestedMessageContent nestedContent = new NestedMessageContent(myPKIMessage);
        boolean ret = nestedContent.verify();
        assertFalse("The message verification failed, yet the a certificate was returned.", ret);
        
    }
    
    @Test
    public void test06NotNestedMessage() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
        
        ASN1EncodableVector optionaValidityV = new ASN1EncodableVector();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        optionaValidityV.add(new DERTaggedObject(true, 0, nb));
        optionaValidityV.add(new DERTaggedObject(true, 1, na));
        OptionalValidity myOptionalValidity = OptionalValidity.getInstance(new DERSequence(optionaValidityV));

        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
        myCertTemplate.setValidity( myOptionalValidity );
        myCertTemplate.setIssuer(new X500Name(issuerDN));
        myCertTemplate.setSubject(new X500Name(subjectDN));
        byte[]                  bytes = keys.getPublic().getEncoded();
        ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream         dIn = new ASN1InputStream(bIn);
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence)dIn.readObject());
        myCertTemplate.setPublicKey(keyInfo);
        // If we did not pass any extensions as parameter, we will create some of our own, standard ones
        
        Extensions exts = null;
        if (exts == null) {
            // SubjectAltName
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            DEROutputStream         dOut = new DEROutputStream(bOut);
            ExtensionsGenerator extgen = new ExtensionsGenerator();
            // KeyUsage
            int bcku = 0;
            bcku = X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment | X509KeyUsage.nonRepudiation;
            X509KeyUsage ku = new X509KeyUsage(bcku);
            bOut = new ByteArrayOutputStream();
            dOut = new DEROutputStream(bOut);
            dOut.writeObject(ku);
            byte[] value = bOut.toByteArray();
            extgen.addExtension(Extension.keyUsage, false, new DEROctetString(value));

            // Make the complete extension package
            exts = extgen.generate();
        }
        myCertTemplate.setExtensions(exts);
        CertRequest myCertRequest = new CertRequest(4, myCertTemplate.build(), null);
        ProofOfPossession myProofOfPossession = new ProofOfPossession();
        AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String("foo123"));
        AttributeTypeAndValue[] avs = {av};
        CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest, myProofOfPossession, avs);

        CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);

        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(subjectDN)), new GeneralName(new X500Name(((X509Certificate)cacert).getSubjectDN().getName())));
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
        PKIBody myPKIBody = new PKIBody(20, myCertReqMessages); // nestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raSignerTest06", "foo123", raKeys, null, null);
        myPKIMessage = CmpMessageHelper.buildCertBasedPKIProtection(myPKIMessage, null, raKeys.getPrivate(), null, "BC");
        
        assertNotNull("Failed to create PKIHeader", myPKIHeader);
        assertNotNull("Failed to create PKIBody", myPKIBody);
        assertNotNull("Failed to create PKIMessage", myPKIMessage);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);

        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        assertEquals("unknown object in getInstance: org.bouncycastle.asn1.DERSequence", errMsg);
    }
    
    @Test
    public void test07ExpiredRACert() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
        log.info(">test07ExpiredRACert()");
        
        //------------------- Creating Certificate Request ---------------
        //PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = null;
        keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage crmfMsg = genCertReq(issuerDN, subjectDN, keys, cacert, senderNonce, transactionID, false, null, 
                nb.getDate(), na.getDate(), null, null, null);
        assertNotNull("Failed to create crmfMsg.", crmfMsg);        
        
        
        
        // ---------------- Creating the NestedMessageContent ----------------------
        
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(reqSubjectDN)), 
                            new GeneralName(new X500Name(((X509Certificate)cacert).getSubjectDN().getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
        myPKIHeader.setRecipNonce(new DEROctetString(nonce));

        PKIBody myPKIBody = new PKIBody(20, crmfMsg); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        
        long nbTime = (new Date()).getTime() - 1000000L;
        nb = new org.bouncycastle.asn1.x509.Time(new Date(nbTime));
        na = new org.bouncycastle.asn1.x509.Time(new Date());
        createRACertificate("raExpiredSignerTest07", "foo123", raKeys, nb.getDate(), na.getDate());
        Thread.sleep(5000);
        myPKIMessage = CmpMessageHelper.buildCertBasedPKIProtection(myPKIMessage, null, raKeys.getPrivate(), null, "BC");
        
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        //final byte[] resp = sendCmpHttp(myPKIMessage.toASN1Primitive().toASN1Object().getEncoded(), 200);
        // do not check signing if we expect a failure (sFailMessage==null)
        
        checkCmpResponseGeneral(resp, issuerDN, reqSubjectDN, cacert, myPKIMessage.getHeader().getSenderNonce().getOctets(), myPKIMessage.getHeader().getTransactionID().getOctets(), false, null);
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        assertEquals("Wrong error message", "Could not verify the RA, signature verification on NestedMessageContent failed.", errMsg);
        log.info("<test07ExpiredRACert()");
    }
    
    @Test
    public void test08MissingSignature() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
        log.info(">test07ExpiredRACert()");

        
        //------------------- Creating Certificate Request ---------------
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = null;
        keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage crmfMsg = genCertReq(issuerDN, subjectDN, keys, cacert, senderNonce, transactionID, false, null, 
                nb.getDate(), na.getDate(), null, null, null);
        assertNotNull("Failed to create crmfMsg.", crmfMsg);        
        
        
        
        // ---------------- Creating the NestedMessageContent ----------------------
        
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(reqSubjectDN)), 
                new GeneralName(new X500Name(((X509Certificate)cacert).getSubjectDN().getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
        myPKIHeader.setRecipNonce(new DEROctetString(nonce));

        PKIBody myPKIBody = new PKIBody(20, crmfMsg); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        //final byte[] resp = sendCmpHttp(myPKIMessage.toASN1Primitive().toASN1Object().getEncoded(), 200);
        // do not check signing if we expect a failure (sFailMessage==null)
        
        checkCmpResponseGeneral(resp, issuerDN, reqSubjectDN, cacert, myPKIMessage.getHeader().getSenderNonce().getOctets(), myPKIMessage.getHeader().getTransactionID().getOctets(), false, null);
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        assertEquals("Wrong error message", "Could not verify the RA, signature verification on NestedMessageContent failed.", errMsg);
        log.info("<test07ExpiredRACert()");
    }
    
    @Test
    public void test09CrmfWrongIssuerAndDoNotCheckAdmin() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-;foo123");

        
        //-----------------Creating CRMF request
        //PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage crmfMsg = genCertReq(issuerDN, subjectDN, keys, cacert, senderNonce, transactionID, false, null, 
                nb.getDate(), na.getDate(), null, pAlg, new DEROctetString(senderNonce));

        KeyPair nonAdminKeys = KeyTools.genKeys("1024", "RSA");
        Certificate nonAdminCert = CertTools.genSelfCert("CN=cmpTestAdmin,C=SE", 365, null, nonAdminKeys.getPrivate(), nonAdminKeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        CMPCertificate cmpcert = getCMPCert(nonAdminCert);
        crmfMsg = CmpMessageHelper.buildCertBasedPKIProtection(crmfMsg, cmpcert, nonAdminKeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(crmfMsg);
        CertReqMessages ir = (CertReqMessages) crmfMsg.getBody().getContent();
        int reqID = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        
        
        //------------------Creating NestedMessageContent
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(reqSubjectDN)), 
                    new GeneralName(new X500Name(((X509Certificate)cacert).getSubjectDN().getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));

        
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( crmfMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody myPKIBody = new PKIBody(20, seq); // NestedMessageContent
        assertNotNull("Failed to create nested Message PKIBody", myPKIBody);
        
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        assertNotNull("Failed to created nested message PKIMessage", myPKIMessage);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raCrmfSigner", "foo123", raKeys, null, null);
        myPKIMessage = CmpMessageHelper.buildCertBasedPKIProtection(myPKIMessage, null, raKeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        //final byte[] resp = sendCmpHttp(myPKIMessage.toASN1Primitive().toASN1Object().getEncoded(), 200);
        // do not check signing if we expect a failure (sFailMessage==null)
        checkCmpResponseGeneral(resp, issuerDN, subjectDN, cacert, crmfMsg.getHeader().getSenderNonce().getOctets(), crmfMsg.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert = checkCmpCertRepMessage(subjectDN, cacert, resp, reqID);
        assertNotNull("CrmfRequest did not return a certificate", cert);
    }   
    
    
    @Test
    public void test23NestedMessageIn3GPPMode() throws Exception {
     
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1");
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        updatePropertyOnServer(CmpConfiguration.CONFIG_3GPPMODE, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_3GPPCA, "3GPPCA");
        updatePropertyOnServer(CmpConfiguration.CONFIG_EXTRACTUSERNAMECOMPONENT, "UID");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY, "true");
        
        byte[] gppCA = Base64.decode( ("MIICHDCCAYWgAwIBAgIId2qio28kX2EwDQYJKoZIhvcNAQEFBQAwHjEPMA0GA1UE" +
                "AwwGM0dQUENBMQswCQYDVQQGEwJTRTAeFw0xMzAxMTYxMTM4MjRaFw0xNDAxMTYx" +
                "MTM4MjRaMB4xDzANBgNVBAMMBjNHUFBDQTELMAkGA1UEBhMCU0UwgZ8wDQYJKoZI" +
                "hvcNAQEBBQADgY0AMIGJAoGBAIK2gGWwWJgcwvB8f83/VAcT3UOiQ1ThZXWetf33" +
                "rcldeMD/7Rydz6SIle0MrDgc9rda4ZdVN+0FJPvL8Q3hcGHUvJeyKGwyf7mJMc8D" +
                "P11qCajZElbmV5Axv8/+i8EZk71XrRLbz8uxSLp84hFe+RQkkJV8hrlV5S8sKGGl" +
                "ebfRAgMBAAGjYzBhMB0GA1UdDgQWBBSZ3XmLRWJOBIt8YUHCETSEdyk4+zAPBgNV" +
                "HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFJndeYtFYk4Ei3xhQcIRNIR3KTj7MA4G" +
                "A1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQUFAAOBgQAsnWEJVneEGwD33JQuSwAH" +
                "c9IT4S7ZM+jrN9ybrJQEV9+dlbfXG8ISdo0aC7RH94vEiVWN2vPcXv1kHcYDmCus" +
                "TB1QaZ/ERhO8SI9x6OHMZ9E4tsgytBsndFadfKKVpODgvXkB6x3/PV96AKz/gpjd" +
                "LYGWSWywpLuutYiiFb6a8w==").getBytes() );

        byte[] gppuser = Base64.decode( ("MIICWzCCAcSgAwIBAgIIAxXKnyDArMYwDQYJKoZIhvcNAQEFBQAwHjEPMA0GA1UE" +
                "AwwGM0dQUENBMQswCQYDVQQGEwJTRTAeFw0xMzAxMTYxMTM0MzhaFw0xNDAxMTYx" +
                "MTM4MjRaMEExGzAZBgoJkiaJk/IsZAEBDAt1aWR1c2VybmFtZTEVMBMGA1UEAwwM" +
                "M2dwcHRlc3R1c2VyMQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw" +
                "gYkCgYEA3mEpApioQ1liwNTvrABdwiieJ9AeImQr5VFoZFDv7NXyoRitMgSZJYNT" +
                "hv1ANPnOTSVpB49n/rVVaniAP+kvdYyZyY3jJUZunQeC6QsdQ+oAE2eTFTyvuJJS" +
                "6bXEertb+Smv9dF+c9NMwLC3KDU4KpO+P9sXim0pCHn2iOWtaWcCAwEAAaN/MH0w" +
                "HQYDVR0OBBYEFJw2zz8wmLbzSP1RHyu5X6/u2X30MAwGA1UdEwEB/wQCMAAwHwYD" +
                "VR0jBBgwFoAUmd15i0ViTgSLfGFBwhE0hHcpOPswDgYDVR0PAQH/BAQDAgXgMB0G" +
                "A1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDANBgkqhkiG9w0BAQUFAAOBgQAG" +
                "VYKkWoysnf999Hxh9jcOC34chJYX0LMqRLpioPEB2uSqDoZgUdpAOJlI/CxLmTJh" +
                "Z/vCqCjWM2CX1T/NmokD3Ea4A0m99y73VEZ4dWtzBi/tFu93XSQzwWXMSRKyYp0/" +
                "SQuEunEJEw76otrAzhCVs3tcKr/+h5F7nMQuOFh1EA==").getBytes() );

        byte[] gppuserkey = Base64.decode( ("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAN5hKQKYqENZYsDU" +
                "76wAXcIonifQHiJkK+VRaGRQ7+zV8qEYrTIEmSWDU4b9QDT5zk0laQePZ/61VWp4" +
                "gD/pL3WMmcmN4yVGbp0HgukLHUPqABNnkxU8r7iSUum1xHq7W/kpr/XRfnPTTMCw" +
                "tyg1OCqTvj/bF4ptKQh59ojlrWlnAgMBAAECgYEA2LBsOa9vJlFPPP9Am6WvtqXF" +
                "lp3g/zoE2+s7gaSsZWcEiZ12BqscX8Vb+smDaxuPvvSZJ1jByRwBI0JQFfau2lcg" +
                "7wqRgjr6Y1rQV6/PsVJLr8xa1iKUgxI9JCktvKu+DT4cHEFMtLlOpIA6niSZP0el" +
                "qiRBzvpsb06Ai4Ng8qECQQDx/CFXxXoIndClM1T6w7snioMapfFgaiq8Ch8c1qoM" +
                "H/fyAfISVqlpmTd6ELHHabjl9hOUDn+0BX2jX5zNYy2LAkEA60JYOv0EruR6560B" +
                "NsnOqiFGYO1zZ583MEGdNXStxSzthplWAEEFkwKdHhaJzW0QQxzhDJqMF+BdTYnQ" +
                "Qh+nFQJANk+FWEK9KfPpoTpNJ18IwU4oMLHv49jQMJYA96MCVWhTaOCg6RbEPSwj" +
                "NGVM0VncItjA+ijq5oeY9DMAaWSKEwJAE3s7+S6Im7752oN+DT5q6bW1sUMYgmUx" +
                "2cIlNY8C8MgGp1W9RGod/w2BW0N8h9FXPmd+z19g6H1A3LHj2AXs/QJAPCWj2EPX" +
                "ZSPn88/rmy8Rrs7owCGvl+v2jeRyDARHF5SVS/7v3pcc8qOxTdWgChS2wv1juvQR" +
                "IgUnBaZUk5bbtw==").getBytes() ); 
        
        
        String testUIDUsername = "uidusername";
        String testUserDN = "CN=3gpptestuse,UID=" + testUIDUsername + ",C=se";
        
        X509Certificate gppcacert = (X509Certificate) CertTools.getCertfromByteArray(gppCA);
        X509Certificate gppusercert = (X509Certificate) CertTools.getCertfromByteArray(gppuser);
        
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(gppuserkey);
        PrivateKey privkey = kf.generatePrivate(ks);
        
        //importing gppcacert as an external CA
        Collection<Certificate> cacerts = new ArrayList<Certificate>();
        cacerts.add(gppcacert);
        caAdminSession.importCACertificate(admin, "3GPPCA", cacerts);
        createUser(testUIDUsername, testUserDN, "foo123");
        
        String fingerprint = null;
        try {
            
            //------------ Creating an CertificationRequest signed by the vendor-issued certificate, not in the database, for an endentity that already exists.
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();
            KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, gppcacert, nonce, transid, false, null, null, null, null, pAlg, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            CMPCertificate extraCert = getCMPCert(gppusercert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, privkey, pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(msg);

            //------------------Creating NestedMessageContent
            String nestedSubjectDN = "CN=nestedSender";
            final byte[] noncen = CmpMessageHelper.createSenderNonce();
            final byte[] transidn = CmpMessageHelper.createSenderNonce();
            
            PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(nestedSubjectDN)), 
                        new GeneralName(new X500Name(((X509Certificate)cacert).getSubjectDN().getName())));
            myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
            // senderNonce
            myPKIHeader.setSenderNonce(new DEROctetString(noncen));
            // TransactionId
            myPKIHeader.setTransactionID(new DEROctetString(transidn));

            
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add( msg );
            DERSequence seq = new DERSequence(v);
            PKIBody myPKIBody = new PKIBody(20, seq); // NestedMessageContent
            assertNotNull("Failed to create nested Message PKIBody", myPKIBody);
            
            PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
            assertNotNull("Failed to created nested message PKIMessage", myPKIMessage);
            KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
            createRACertificate("raCrmfSigner", "foo123", raKeys, null, null);
            myPKIMessage = CmpMessageHelper.buildCertBasedPKIProtection(myPKIMessage, null, raKeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull("Failed to create myPKIHeader", myPKIHeader);
            assertNotNull("myPKIBody is null", myPKIBody);
            assertNotNull("myPKIMessage is null", myPKIMessage);
            
            //-------------- sending the request
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(msg);
            byte[] ba = bao.toByteArray();
            byte[] resp = sendCmpHttp(ba, 200);
            CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
            Certificate cert = checkCmpCertRepMessage(testUserDN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                    .getValue().intValue());
            assertNotNull("CrmfRequest did not return a certificate", cert);
            fingerprint = CertTools.getFingerprintAsString(cert);
        } finally {
            try {
                endEntityManagementSession.revokeAndDeleteUser(admin, testUIDUsername, ReasonFlags.unused);
                caSession.removeCA(admin, CertTools.getIssuerDN(gppcacert).hashCode());
            } catch (Exception e) {}

            internalCertStoreSession.removeCertificate(fingerprint);

        }
    }
    
    @Test
    public void testZZZCleanUp() throws Exception {
        log.trace(">testZZZCleanUp");
        
        try {
            endEntityManagementSession.revokeAndDeleteUser(admin, "cmpTestAdmin", ReasonFlags.keyCompromise);
        } catch(Exception e){
            // NOPMD
        }
        try {
            endEntityManagementSession.revokeAndDeleteUser(admin, "nestedCMPTest", ReasonFlags.keyCompromise);
        } catch(Exception e){
            // NOPMD
        }
        
        certProfileSession.removeCertificateProfile(admin, "CMPTESTPROFILE");        
        eeProfileSession.removeEndEntityProfile(admin, "CMPTESTPROFILE");
        
        assertTrue("Could not restore CMP configurations", configurationSession.restoreConfiguration());
        
        log.trace("<testZZZCleanUp");
    }
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        
        File createdFolder = new File(raCertsPath);
        File[] certs = createdFolder.listFiles();
        for(int i=0; i<certs.length; i++) {
            certs[i].delete();
        }
        createdFolder.delete();
    }
    
    
    
    
    

    private Certificate createRACertificate(String username, String password, KeyPair keys, Date notBefore, 
            Date notAfter) throws AuthorizationDeniedException, EjbcaException, CertificateException, FileNotFoundException,
            IOException, UserDoesntFullfillEndEntityProfile, ObjectNotFoundException, Exception {
        
        assertTrue("RACertPath is suppose to be '" + raCertsPath + "', instead it is '" + configurationSession.getProperty(CmpConfiguration.CONFIG_RACERT_PATH) + "'.", configurationSession.verifyProperty(CmpConfiguration.CONFIG_RACERT_PATH, raCertsPath));
        
        createUser(username, "CN="+username, password);
        Certificate racert = signSession.createCertificate(admin, username, password, keys.getPublic(), X509KeyUsage.digitalSignature|X509KeyUsage.keyCertSign, notBefore, notAfter, certProfileSession.getCertificateProfileId("CMPTESTPROFILE"), caid);

        
        Vector<Certificate> certCollection = new Vector<Certificate>();
        certCollection.add(racert);
        byte[] pemRaCert = CertTools.getPEMFromCerts(certCollection);
        
        String raCertPath = configurationSession.getProperty(CmpConfiguration.CONFIG_RACERT_PATH);
        String filename = raCertPath + "/" + username + ".pem";
        File file = folder.newFile(filename);
        assertNotNull(file);
        FileOutputStream fout = new FileOutputStream(file);
        fout.write(pemRaCert);
        fout.flush();
        fout.close();        
        
        endEntityManagementSession.deleteUser(admin, username);
        
        return racert;
    }

    private EndEntityInformation createUser(String username, String subjectDN, String password) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException,
            EjbcaException, Exception {
        
        EndEntityInformation user = new EndEntityInformation(username, subjectDN, caid, null, username+"@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            endEntityManagementSession.addUser(admin, user, false);
            // usersession.addUser(admin,"cmptest","foo123",userDN,null,"cmptest@primekey.se",false,SecConst.EMPTY_ENDENTITYPROFILE,CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,EndEntityTypes.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: " + username);
        } catch (Exception e) {
            log.debug("User " + username + " already exists. Setting the user status to NEW");
            endEntityManagementSession.changeUser(admin, user, false);
            endEntityManagementSession.setUserStatus(admin, username, EndEntityConstants.STATUS_NEW);
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
        roleManagementSession.addSubjectsToRole(admin, roledata, accessUsers);

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
                certificate = (X509Certificate) signSession.createCertificate(admin, adminName, "foo123", keys.getPublic());
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
            } catch (javax.ejb.ObjectNotFoundException e) {
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
            
            roleManagementSession.removeSubjectsFromRole(admin, roledata, accessUsers);
        }
        
        endEntityManagementSession.revokeAndDeleteUser(admin, adminName, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);        
    }
    
    private CMPCertificate getCMPCert(Certificate cert) throws CertificateEncodingException, IOException {
        ASN1InputStream ins = new ASN1InputStream(cert.getEncoded());
        ASN1Primitive pcert = ins.readObject();
        org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate.getInstance(pcert.toASN1Primitive());
        return new CMPCertificate(c); //new CMPCertificate(new AttributeCertificate((ASN1Sequence) pcert.toASN1Primitive()));        
    }

    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    

}
