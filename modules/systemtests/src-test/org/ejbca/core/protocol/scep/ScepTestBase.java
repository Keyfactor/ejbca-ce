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
package org.ejbca.core.protocol.scep;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/**
 *
 */
public abstract class ScepTestBase {
    
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ScepTestBase"));
    
    private static final Logger log = Logger.getLogger(ScepTestBase.class);

    
    private final ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

    
    protected final String httpReqPath;
    
    public ScepTestBase() {
        final String httpHost = SystemTestsConfiguration.getRemoteHost(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        final String httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        httpReqPath = "http://" + httpHost + ":" + httpPort + "/ejbca";
        
    }
    
    protected void checkCACaps(String caname, String expectedCaps) throws IOException {
        byte[] respBytes = sendGetCACapsRequest(caname, 200);
        assertNotNull("Response can not be null.", respBytes);
        assertTrue(respBytes.length > 0);
        assertEquals(expectedCaps, new String(respBytes));
    }
    
    protected abstract String getResourceScep();
    
    protected byte[] sendGetCACapsRequest(final String caname, final int expectedStatusCode) throws IOException {
        final String reqUrl = httpReqPath + '/' + getResourceScep() + "?operation=GetCACaps&message=" + URLEncoder.encode(caname, "UTF-8");
        final URL url = new URL(reqUrl);
        final HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        assertEquals("Response code was wrong.", expectedStatusCode, con.getResponseCode());
        if (expectedStatusCode != 200) {
            return null;
        }
        // Some appserver (Weblogic) responds with "text/plain; charset=UTF-8"
        assertTrue(con.getContentType().startsWith("text/plain"));
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        try (final InputStream in = con.getInputStream()) {
            int b = in.read();
            while (b != -1) {
                baos.write(b);
                b = in.read();
            }
        }
        return baos.toByteArray();
    }
    
    protected EndEntityInformation createEndEntityInformation(String userName, String userDN, int caId) {
        final EndEntityInformation data = new EndEntityInformation(userName, userDN, caId, null, "sceptest@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, null);
        data.setPassword("foo123");
        data.setStatus(EndEntityConstants.STATUS_NEW);
        return data;
    }
    
    protected void createScepUser(String userName, String userDN, int caId)
            throws EndEntityExistsException, CADoesntExistsException, AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, EjbcaException, IllegalNameException, CertificateSerialNumberException, NoSuchEndEntityException {
        if(!endEntityManagementSession.existsUser(userName)) {
            endEntityManagementSession.addUser(admin, createEndEntityInformation(userName, userDN, caId), false);
        } else {
            changeScepUser(userName, userDN, caId);
        }
    }
    
    protected void changeScepUser(String userName, String userDN, int caId)
            throws CADoesntExistsException, AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException,
            EjbcaException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException {
        endEntityManagementSession.changeUser(admin, createEndEntityInformation(userName, userDN, caId), false);
        log.debug("changing user: " + userName + ", foo123, " + userDN);
    }
    
    protected byte[] sendScep(boolean post, byte[] scepPackage) throws IOException {
        return sendScep(post, scepPackage, HttpServletResponse.SC_OK);
    }

    protected byte[] sendScep(boolean post, byte[] scepPackage, int responseCode) throws IOException {
        // POST the SCEP request
        // we are going to do a POST
        String urlString = httpReqPath + '/' + getResourceScep() + "?operation=PKIOperation";
        log.debug("UrlString =" + urlString);
        final HttpURLConnection con;
        if (post) {
            URL url = new URL(urlString);
            con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setRequestMethod("POST");
            con.connect();
            // POST it
            OutputStream os = con.getOutputStream();
            os.write(scepPackage);
            os.close();
        } else {
            String reqUrl = urlString + "&message=" + URLEncoder.encode(new String(Base64.encode(scepPackage)), "UTF-8");
            URL url = new URL(reqUrl);
            con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
        }

        assertEquals("Response code", responseCode, con.getResponseCode());
        // Some appserver (Weblogic) responds with
        // "application/x-pki-message; charset=UTF-8"
        if (responseCode == HttpServletResponse.SC_OK) {
            assertTrue(con.getContentType().startsWith("application/x-pki-message"));
        } else {
            assertTrue(con.getContentType().startsWith("text/html"));
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        final InputStream in;
        if (responseCode == HttpServletResponse.SC_OK) {
            in = con.getInputStream();
        } else {
            in = con.getErrorStream();
        }
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        assertNotNull("Response can not be null.", respBytes);
        assertTrue(respBytes.length > 0);
        return respBytes;
    }
    
    protected abstract String getTransactionId();
    
    protected abstract X509Certificate getCaCertificate();
    
    protected void checkScepResponse(byte[] retMsg, String userDN, String _senderNonce, String _transId, boolean crlRep, String digestOid,
            boolean noca, ASN1ObjectIdentifier encryptionAlg, KeyPair keyPair) throws CMSException, OperatorCreationException,
            NoSuchProviderException, CRLException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, CertificateException {
        checkScepResponse(retMsg, userDN, -1L, _senderNonce, getTransactionId(), crlRep, digestOid, noca, getCaCertificate(), keyPair, encryptionAlg);
    }
    
    protected void checkScepResponse(byte[] retMsg, String userDN, long startValidity, String _senderNonce, String transId, boolean crlRep, String digestOid, boolean noca,
                                   X509Certificate caCertToUse, KeyPair key, ASN1ObjectIdentifier encryptionAlg)
            throws CMSException, OperatorCreationException, NoSuchProviderException, CRLException, InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, CertificateException {

        // Parse response message
        //
        CMSSignedData s = new CMSSignedData(retMsg);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        Collection<SignerInformation> col = signers.getSigners();
        assertTrue(col.size() > 0);
        Iterator<SignerInformation> iter = col.iterator();
        SignerInformation signerInfo = iter.next();
        // Check that the message is signed with the correct digest alg
        assertEquals(signerInfo.getDigestAlgOID(), digestOid);
        SignerId sinfo = signerInfo.getSID();
        // Check that the signer is the expected CA
        assertEquals(CertTools.stringToBCDNString(getCaCertificate().getIssuerDN().getName()), CertTools.stringToBCDNString(sinfo.getIssuer().toString()));
        // Verify the signature
        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
        JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(calculatorProviderBuilder.build()).setProvider(BouncyCastleProvider.PROVIDER_NAME);
        boolean ret = signerInfo.verify(jcaSignerInfoVerifierBuilder.build(caCertToUse.getPublicKey()));
        assertTrue("signature verification of response failed", ret);
        // Get authenticated attributes
        AttributeTable tab = signerInfo.getSignedAttributes();
        // --Fail info
        Attribute attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_failInfo));
        // No failInfo on this success message
        assertNull(attr);
        // --Message type
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_messageType));
        assertNotNull(attr);
        ASN1Set values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        ASN1String str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        String messageType = str.getString();
        assertEquals("3", messageType);
        // --Success status
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        assertEquals(ResponseStatus.SUCCESS.getStringValue(), str.getString());
        // --SenderNonce
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_senderNonce));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        ASN1OctetString octstr = ASN1OctetString.getInstance(values.getObjectAt(0));
        // SenderNonce is something the server came up with, but it should be 16
        // chars
        assertTrue(octstr.getOctets().length == 16);
        // --Recipient Nonce
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_recipientNonce));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        octstr = ASN1OctetString.getInstance(values.getObjectAt(0));
        // recipient nonce should be the same as we sent away as sender nonce
        assertEquals(_senderNonce, new String(Base64.encode(octstr.getOctets())));
        // --Transaction ID
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_transId));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        // transid should be the same as the one we sent
        assertEquals(transId, str.getString());

        //
        // Check different message types
        //
        if (messageType.equals("3")) {
            // First we extract the encrypted data from the CMS enveloped data
            // contained
            // within the CMS signed data
            final CMSProcessable sp = s.getSignedContent();
            final byte[] content = (byte[]) sp.getContent();
            final CMSEnvelopedData ed = new CMSEnvelopedData(content);
            final RecipientInformationStore recipients = ed.getRecipientInfos();
            @SuppressWarnings("rawtypes")
            Store certstore;

            Collection<RecipientInformation> c = recipients.getRecipients();
            assertEquals(c.size(), 1);
            Iterator<RecipientInformation> riIterator = c.iterator();
            byte[] decBytes = null;
            RecipientInformation recipient = riIterator.next();
            JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(key.getPrivate());
            rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
            // Option we must set to prevent Java PKCS#11 provider to try to make the symmetric decryption in the HSM, 
            // even though we set content provider to BC. Symm decryption in HSM varies between different HSMs and at least for this case is known 
            // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where they introduced imho a buggy behavior)
            rec.setMustProduceEncodableUnwrappedKey(true);            
            decBytes = recipient.getContent(rec);
            String encAlg = ed.getContentEncryptionAlgorithm().getAlgorithm().getId();
            // Was it the expected encryption algo from the server?
            log.debug("Encryption algorithm from the server is: " + encAlg);
            assertEquals("The server did not encrypt with the expected encryption algorithm", encryptionAlg.getId(), encAlg);
            // This is yet another CMS signed data
            CMSSignedData sd = new CMSSignedData(decBytes);
            // Get certificates from the signed data
            certstore = sd.getCertificates();

            if (crlRep) {
                // We got a reply with a requested CRL
                final Collection<X509CRLHolder> crls = sd.getCRLs().getMatches(null);
                assertEquals(crls.size(), 1);
                final Iterator<X509CRLHolder> it = crls.iterator();
                // CRL is first (and only)
                final X509CRL retCrl = new JcaX509CRLConverter().getCRL(it.next());
                log.info("Got CRL with DN: " + retCrl.getIssuerDN().getName());

                // check the returned CRL
                assertEquals(CertTools.getSubjectDN(caCertToUse), CertTools.getIssuerDN(retCrl));
                retCrl.verify(caCertToUse.getPublicKey());
            } else {
                // We got a reply with a requested certificate
                @SuppressWarnings("unchecked")
                final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
                // EJBCA returns the issued cert and the CA cert (cisco vpn
                // client requires that the ca cert is included)
                if (noca) {
                    assertEquals(certs.size(), 1);
                } else {
                    assertEquals(certs.size(), 2);
                }
                final Iterator<X509CertificateHolder> it = certs.iterator();
                // Issued certificate must be first
                boolean verified = false;
                boolean gotcacert = false;
                JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
                while (it.hasNext()) {
                    X509Certificate retcert = jcaX509CertificateConverter.getCertificate(it.next());
                    log.info("Got cert with DN: " + retcert.getSubjectDN().getName());

                    // check the returned certificate
                    String subjectdn = CertTools.stringToBCDNString(retcert.getSubjectDN().getName());
                    if (CertTools.stringToBCDNString(userDN).equals(subjectdn)) {
                        // issued certificate
                        assertEquals(CertTools.stringToBCDNString(userDN), subjectdn);
                        assertEquals(CertTools.getSubjectDN(caCertToUse), CertTools.getIssuerDN(retcert));
                        retcert.verify(caCertToUse.getPublicKey());
                        assertTrue(checkKeys(key.getPrivate(), retcert.getPublicKey()));
                        
                        if (startValidity != -1L) {
                            long certValidityStart = retcert.getNotBefore().getTime();
                            if (Math.abs(certValidityStart - startValidity) > 60L*1000L) {
                                assertEquals("wrong start validity time of issued user certificate", startValidity, certValidityStart);
                            }
                        }
                        verified = true;
                    } else {
                        // ca certificate
                        assertEquals(CertTools.getSubjectDN(caCertToUse), CertTools.getSubjectDN(retcert));
                        gotcacert = true;
                    }
                }
                assertTrue(verified);
                if (noca) {
                    assertFalse(gotcacert);
                } else {
                    assertTrue(gotcacert);
                }
            }
        }

    }
    

    /**
     * checks that a public and private key matches by signing and verifying a message
     */
    private boolean checkKeys(PrivateKey priv, PublicKey pub) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        Signature signer = Signature.getInstance("SHA1WithRSA");
        signer.initSign(priv);
        signer.update("PrimeKey".getBytes());
        byte[] signature = signer.sign();

        Signature signer2 = Signature.getInstance("SHA1WithRSA");
        signer2.initVerify(pub);
        signer2.update("PrimeKey".getBytes());
        return signer2.verify(signature);
    }

}
