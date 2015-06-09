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

package org.ejbca.core.protocol.xkms;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.apache.xml.security.utils.XMLUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.protocol.ws.BatchCreateTool;
import org.ejbca.core.protocol.xkms.client.XKMSInvoker;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.core.protocol.xkms.common.XKMSUtil;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.PrototypeKeyBindingType;
import org.w3._2002._03.xkms_.QueryKeyBindingType;
import org.w3._2002._03.xkms_.RegisterRequestType;
import org.w3._2002._03.xkms_.UseKeyWithType;
import org.w3._2002._03.xkms_.ValidateRequestType;
import org.w3._2002._03.xkms_.ValidateResultType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * To Run this test, there must be a CA with DN
 * "CN=ManagementCA,O=EJBCA Sample,C=SE", and it must have XKMS service enabled.
 * Also you have to enable XKMS in conf/xkms.properties.
 * 
 * @version $Id$
 */

public class XKMSSigTest {

    private static final Logger log = Logger.getLogger(XKMSSigTest.class);
    
    private ObjectFactory xKMSObjectFactory = new ObjectFactory();
    private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();

    private static final String SERVICE_URL = "http://localhost:8080/ejbca/xkms/xkms";	//http://localhost:8080/ejbca/xkms/xkms
    
    private static final String P12_FOLDER_NAME = "p12";
    
    private static String baseUsername;

    private static String username;
    private static File tmpfile;
    private static File keystorefile;

    private static JAXBContext jAXBContext = null;
    private static Marshaller marshaller = null;
    private static DocumentBuilderFactory dbf = null;

    private static int caid;

    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

	private AuthenticationToken administrator = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("XKMSSigTest"));

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        org.apache.xml.security.Init.init();

        jAXBContext = JAXBContext.newInstance("org.w3._2002._03.xkms_:org.w3._2001._04.xmlenc_:org.w3._2000._09.xmldsig_");
        marshaller = XKMSUtil.getNamespacePrefixMappedMarshaller(jAXBContext);
        dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        
        caid = CertTools.stringToBCDNString("CN=ManagementCA,O=EJBCA Sample,C=SE").hashCode();
        Random ran = new Random();
        if (baseUsername == null) {
            baseUsername = "xkmstestadmin" + (ran.nextInt() % 1000) + "-";
        }
        
        username = baseUsername + "1";
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        AuthenticationToken administrator = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("XKMSSigTest"));
        try {
            endEntityManagementSession.addUser(administrator, username, "foo123", "CN=superadmin", null, null, false, SecConst.EMPTY_ENDENTITYPROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ADMINISTRATOR.toEndEntityType(), SecConst.TOKEN_SOFT_JKS, 0, caid);
            endEntityManagementSession.setClearTextPassword(administrator, username, "foo123");
        } catch (Exception e) {
            assertTrue("Failed to create user " + username, false);
        }

        tmpfile = new File("p12");
        BatchCreateTool.createAllNew(administrator, tmpfile.getParentFile());

    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        AuthenticationToken administrator = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("XKMSSigTest"));
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        endEntityManagementSession.deleteUser(administrator, username);
        keystorefile.deleteOnExit();
    }

    @After
    public void tearDown() throws Exception {
    }



    @Test
    public void test01ClientSignature() throws Exception {
    	log.trace(">test01ClientSignature");
        KeyStore clientKeyStore = Constants.getUserKeyStore();

        // Test simple validate
        ValidateRequestType validateRequestType = xKMSObjectFactory.createValidateRequestType();
        validateRequestType.setId("200");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier("Test");

        validateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        validateRequestType.setQueryKeyBinding(queryKeyBindingType);

        JAXBElement<ValidateRequestType> validateRequest = xKMSObjectFactory.createValidateRequest(validateRequestType);

        String alias = "TEST";
        java.security.cert.X509Certificate pkCert = (java.security.cert.X509Certificate) clientKeyStore.getCertificate(alias);

        Key key = clientKeyStore.getKey(alias, "foo123".toCharArray());

        Document doc = dbf.newDocumentBuilder().newDocument();
        marshaller.marshal(validateRequest, doc);

        org.apache.xml.security.signature.XMLSignature xmlSig = new org.apache.xml.security.signature.XMLSignature(doc, "",
                org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
                org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        org.apache.xml.security.transforms.Transforms transforms = new org.apache.xml.security.transforms.Transforms(doc);
        transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        xmlSig.addDocument("#" + validateRequest.getValue().getId(), transforms, org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);
        xmlSig.addKeyInfo(pkCert);
        doc.getDocumentElement().insertBefore(xmlSig.getElement(), doc.getDocumentElement().getFirstChild());
        xmlSig.sign(key);

        // DOMSource dOMSource = new DOMSource(doc);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, baos);
        log.debug("XMLUtils.outputDOMc14nWithComments: " + baos.toString());
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc2 = db.parse(bais);
        ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc2, baos2);
        log.debug("XMLUtils.outputDOMc14nWithComments: " + baos2.toString());

        org.w3c.dom.NodeList xmlSigs = doc2.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        org.w3c.dom.Element xmlSigElement = (org.w3c.dom.Element) xmlSigs.item(0);
        org.apache.xml.security.signature.XMLSignature xmlVerifySig = new org.apache.xml.security.signature.XMLSignature(xmlSigElement, null);

        org.apache.xml.security.keys.KeyInfo keyInfo = xmlVerifySig.getKeyInfo();
        java.security.cert.X509Certificate verCert = keyInfo.getX509Certificate();

        assertTrue(xmlVerifySig.checkSignatureValue(verCert));
    	log.trace("<test01ClientSignature");
    }

    @Test
    public void test02SendSignedRequest() throws Exception {
    	log.trace(">test02SendSignedRequest");
        KeyStore clientKeyStore = KeyStore.getInstance("JKS");
        keystorefile = new File(tmpfile.getAbsolutePath() + "/" + username + ".jks");
        clientKeyStore.load(new FileInputStream(keystorefile), "foo123".toCharArray());

        String alias = "superadmin";
        java.security.cert.X509Certificate pkCert = (java.security.cert.X509Certificate) clientKeyStore.getCertificate(alias);
        assertNotNull("Unable to get certificate for admin.", pkCert);
        Key key = clientKeyStore.getKey(alias, "foo123".toCharArray());
        assertNotNull("Unable to get key for admin.", pkCert);
        Certificate[] trustedcerts = clientKeyStore.getCertificateChain(alias);
        ArrayList<Certificate> trustcol = new ArrayList<Certificate>();
        for (int i = 0; i < trustedcerts.length; i++) {
            if (((X509Certificate) trustedcerts[i]).getBasicConstraints() != -1) {
                trustcol.add(trustedcerts[i]);
            }
        }

        XKMSInvoker xKMSInvoker = new XKMSInvoker(SERVICE_URL, trustcol);

        // Test simple validate
        ValidateRequestType validateRequestType = xKMSObjectFactory.createValidateRequestType();
        validateRequestType.setId("200");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier("Test");

        validateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        validateRequestType.setQueryKeyBinding(queryKeyBindingType);

        JAXBElement<ValidateRequestType> validateRequest = xKMSObjectFactory.createValidateRequest(validateRequestType);

        Document doc = dbf.newDocumentBuilder().newDocument();
        marshaller.marshal(validateRequest, doc);
        try {
            ValidateResultType validateResultType = xKMSInvoker.validate(validateRequestType, pkCert, key);
            assertTrue(validateResultType.getRequestId().equals("200"));
            assertTrue(validateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        } catch (javax.xml.ws.soap.SOAPFaultException e) {
            log.debug("", e);
            assertTrue("There was a server error. (" + e.getMessage() + ") Did you enable the XKMS CA service?", false);
        }
    	log.trace("<test02SendSignedRequest");
    }

    @Test
   public void test03SendUntrustedRequest() throws Exception {
    	log.trace(">test03SendUntrustedRequest");
        KeyStore clientKeyStore = Constants.getUserKeyStore();
        KeyStore trustKeyStore = KeyStore.getInstance("JKS");
        keystorefile = new File(tmpfile.getAbsolutePath() + "/" + username + ".jks");
        trustKeyStore.load(new FileInputStream(keystorefile), "foo123".toCharArray());

        String alias = "TEST";
        java.security.cert.X509Certificate pkCert = (java.security.cert.X509Certificate) clientKeyStore.getCertificate(alias);
        Key key = clientKeyStore.getKey(alias, "foo123".toCharArray());
        Certificate[] trustedcerts = trustKeyStore.getCertificateChain("superadmin");
        ArrayList<Certificate> trustcol = new ArrayList<Certificate>();
        for (int i = 0; i < trustedcerts.length; i++) {
            if (((X509Certificate) trustedcerts[i]).getBasicConstraints() != -1) {
                trustcol.add(trustedcerts[i]);
            }
        }

        XKMSInvoker xKMSInvoker = new XKMSInvoker(SERVICE_URL, trustcol);

        // Test simple validate
        ValidateRequestType validateRequestType = xKMSObjectFactory.createValidateRequestType();
        validateRequestType.setId("201");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier("Test");

        validateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        validateRequestType.setQueryKeyBinding(queryKeyBindingType);

        JAXBElement<ValidateRequestType> validateRequest = xKMSObjectFactory.createValidateRequest(validateRequestType);

        Document doc = dbf.newDocumentBuilder().newDocument();
        marshaller.marshal(validateRequest, doc);

        try {
            ValidateResultType validateResultType = xKMSInvoker.validate(validateRequestType, pkCert, key);
            assertTrue(validateResultType.getRequestId().equals("201"));
            assertTrue(validateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
            assertTrue(validateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION));
        } catch (javax.xml.ws.soap.SOAPFaultException e) {
            log.debug("", e);
            assertTrue("There was a server error. (" + e.getMessage() + ") Did you enable the XKMS CA service?", false);
        }
    	log.trace("<test03SendUntrustedRequest");
    }

    @Test
    public void test04SendRevokedRequest() throws Exception {
    	log.trace(">test04SendRevokedRequest");
        endEntityManagementSession.revokeUser(administrator, username, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);

        KeyStore clientKeyStore = KeyStore.getInstance("JKS");
        keystorefile = new File(tmpfile.getAbsolutePath() + "/" + username + ".jks");
        clientKeyStore.load(new FileInputStream(keystorefile), "foo123".toCharArray());

        String alias = "superadmin";
        java.security.cert.X509Certificate pkCert = (java.security.cert.X509Certificate) clientKeyStore.getCertificate(alias);
        Key key = clientKeyStore.getKey(alias, "foo123".toCharArray());
        Certificate[] trustedcerts = clientKeyStore.getCertificateChain(alias);
        ArrayList<Certificate> trustcol = new ArrayList<Certificate>();
        for (int i = 0; i < trustedcerts.length; i++) {
            if (((X509Certificate) trustedcerts[i]).getBasicConstraints() != -1) {
                trustcol.add(trustedcerts[i]);
            }
        }

        XKMSInvoker xKMSInvoker = new XKMSInvoker(SERVICE_URL, trustcol);

        // Test simple validate
        ValidateRequestType validateRequestType = xKMSObjectFactory.createValidateRequestType();
        validateRequestType.setId("200");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier("Test");

        validateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        validateRequestType.setQueryKeyBinding(queryKeyBindingType);

        JAXBElement<ValidateRequestType> validateRequest = xKMSObjectFactory.createValidateRequest(validateRequestType);

        Document doc = dbf.newDocumentBuilder().newDocument();
        marshaller.marshal(validateRequest, doc);

        try {
            ValidateResultType validateResultType = xKMSInvoker.validate(validateRequestType, pkCert, key);
            assertTrue(validateResultType.getRequestId().equals("200"));
            assertTrue(validateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
            assertTrue(validateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION));
        } catch (javax.xml.ws.soap.SOAPFaultException e) {
            log.debug("", e);
            assertTrue("There was a server error. (" + e.getMessage() + ") Did you enable the XKMS CA service?", false);
        }
    	log.trace("<test04SendRevokedRequest");
    }

    @Test
    public void test05POPSignature() throws Exception {
    	log.trace(">test05POPSignature");
        KeyStore clientKeyStore = Constants.getUserKeyStore();

        String alias = "TEST";
        java.security.cert.X509Certificate pkCert = (java.security.cert.X509Certificate) clientKeyStore.getCertificate(alias);

        Key key = clientKeyStore.getKey(alias, "foo123".toCharArray());

        RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
        registerRequestType.setId("500");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier("CN=Test Testarsson");

        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) pkCert.getPublicKey()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) pkCert.getPublicKey()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);
        JAXBElement<RegisterRequestType> registerRequest = xKMSObjectFactory.createRegisterRequest(registerRequestType);

        Document registerRequestDoc = dbf.newDocumentBuilder().newDocument();
        marshaller.marshal(registerRequest, registerRequestDoc);

        Element prototypeKeyBindingTag = (Element) registerRequestDoc.getDocumentElement().getElementsByTagNameNS("http://www.w3.org/2002/03/xkms#",
                "PrototypeKeyBinding").item(0);
        assertTrue(prototypeKeyBindingTag != null);

        org.apache.xml.security.signature.XMLSignature xmlSig = new org.apache.xml.security.signature.XMLSignature(registerRequestDoc, "",
                org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
                org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        org.apache.xml.security.transforms.Transforms transforms = new org.apache.xml.security.transforms.Transforms(registerRequestDoc);
        transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        xmlSig.addDocument("#" + prototypeKeyBindingType.getId(), transforms, org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);

        xmlSig.sign(key);

        Element pOPElement = registerRequestDoc.createElementNS("http://www.w3.org/2002/03/xkms#", "ProofOfPossession");
        pOPElement.appendChild(xmlSig.getElement().cloneNode(true));
        registerRequestDoc.getDocumentElement().appendChild(pOPElement);

        ByteArrayOutputStream logBaos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(registerRequestDoc, logBaos);
        log.info("XMLUtils.outputDOMc14nWithComments: " + logBaos.toString());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(registerRequestDoc, baos);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

        Document doc2 = db.parse(bais);
        logBaos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc2, logBaos);
        log.info("XMLUtils.outputDOMc14nWithComments: " + logBaos.toString());

        org.w3c.dom.NodeList xmlSigs = doc2.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        org.w3c.dom.Element xmlSigElement = (org.w3c.dom.Element) xmlSigs.item(0);
        org.apache.xml.security.signature.XMLSignature xmlVerifySig = new org.apache.xml.security.signature.XMLSignature(xmlSigElement, null);

        assertTrue(xmlVerifySig.checkSignatureValue(pkCert.getPublicKey()));

        KeyPair keyPair = KeyTools.genKeys("1024", "RSA");
        assertFalse(xmlVerifySig.checkSignatureValue(keyPair.getPublic()));
    	log.trace("<test05POPSignature");
    }

    @Test
    public void test06AuthenticationKeyBindingSignature() throws Exception {
    	log.trace(">test06AuthenticationKeyBindingSignature");
        KeyStore clientKeyStore = Constants.getUserKeyStore();
        KeyPair keyPair = KeyTools.genKeys("1024", "RSA");

        String alias = "TEST";
        java.security.cert.X509Certificate pkCert = (java.security.cert.X509Certificate) clientKeyStore.getCertificate(alias);

        RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
        registerRequestType.setId("500");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier("CN=Test Testarsson");

        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keyPair.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keyPair.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);
        JAXBElement<RegisterRequestType> registerRequest = xKMSObjectFactory.createRegisterRequest(registerRequestType);

        Document registerRequestDoc = dbf.newDocumentBuilder().newDocument();
        marshaller.marshal(registerRequest, registerRequestDoc);

        String authenticationData = "024837";

        SecretKey sk = XKMSUtil.getSecretKeyFromPassphrase(authenticationData, true, 20, XKMSUtil.KEY_AUTHENTICATION);

        org.apache.xml.security.signature.XMLSignature authXMLSig = new org.apache.xml.security.signature.XMLSignature(registerRequestDoc, "",
                org.apache.xml.security.signature.XMLSignature.ALGO_ID_MAC_HMAC_SHA1,
                org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        org.apache.xml.security.transforms.Transforms transforms = new org.apache.xml.security.transforms.Transforms(registerRequestDoc);
        transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        authXMLSig.addDocument("#" + prototypeKeyBindingType.getId(), transforms, org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);

        authXMLSig.sign(sk);

        Element authenticationElement = registerRequestDoc.createElementNS("http://www.w3.org/2002/03/xkms#", "Authentication");
        Element keyBindingAuthenticationElement = registerRequestDoc.createElementNS("http://www.w3.org/2002/03/xkms#", "KeyBindingAuthentication");
        keyBindingAuthenticationElement.appendChild(authXMLSig.getElement().cloneNode(true));
        authenticationElement.appendChild(keyBindingAuthenticationElement);
        registerRequestDoc.getDocumentElement().appendChild(authenticationElement);

        org.apache.xml.security.signature.XMLSignature xmlSig = new org.apache.xml.security.signature.XMLSignature(registerRequestDoc, "",
                org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
                org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        transforms = new org.apache.xml.security.transforms.Transforms(registerRequestDoc);
        transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        xmlSig.addDocument("#" + prototypeKeyBindingType.getId(), transforms, org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);

        xmlSig.sign(keyPair.getPrivate());

        Element pOPElement = registerRequestDoc.createElementNS("http://www.w3.org/2002/03/xkms#", "ProofOfPossession");
        pOPElement.appendChild(xmlSig.getElement().cloneNode(true));
        registerRequestDoc.getDocumentElement().appendChild(pOPElement);

        ByteArrayOutputStream logBaos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(registerRequestDoc, logBaos);
        log.info("XMLUtils.outputDOMc14nWithComments: " + logBaos.toString());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(registerRequestDoc, baos);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc2 = db.parse(bais);
        logBaos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc2, logBaos);
        log.info("XMLUtils.outputDOMc14nWithComments: " + logBaos.toString());

        // Verify the authentication
        org.w3c.dom.NodeList authenticationElements = doc2.getElementsByTagNameNS("http://www.w3.org/2002/03/xkms#", "Authentication");
        assertTrue("Missing \"Authentication\" element in doc.", authenticationElements.getLength() == 1);
        Element ae = (Element) authenticationElements.item(0);

        org.w3c.dom.NodeList xmlSigs = ae.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");

        org.w3c.dom.Element xmlSigElement = (org.w3c.dom.Element) xmlSigs.item(0);
        org.apache.xml.security.signature.XMLSignature xmlVerifySig = new org.apache.xml.security.signature.XMLSignature(xmlSigElement, null);

        assertTrue("Signature verificate failed.", xmlVerifySig.checkSignatureValue(sk));

        // Verify the pop
        org.w3c.dom.NodeList pOPElements = doc2.getElementsByTagNameNS("http://www.w3.org/2002/03/xkms#", "ProofOfPossession");
        assertTrue(pOPElements.getLength() == 1);
        Element pOPe = (Element) pOPElements.item(0);
        org.w3c.dom.NodeList popVerXmlSigs = pOPe.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        assertTrue(popVerXmlSigs.getLength() == 1);
        org.w3c.dom.Element popVerXmlSigElement = (org.w3c.dom.Element) popVerXmlSigs.item(0);
        org.apache.xml.security.signature.XMLSignature popVerXmlSig = new org.apache.xml.security.signature.XMLSignature(popVerXmlSigElement, null);
        assertTrue(popVerXmlSig.checkSignatureValue(keyPair.getPublic()));
        assertFalse(popVerXmlSig.checkSignatureValue(pkCert.getPublicKey()));
    	log.trace("<test06AuthenticationKeyBindingSignature");
    }


}
