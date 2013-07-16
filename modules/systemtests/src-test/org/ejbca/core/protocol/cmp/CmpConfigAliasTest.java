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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.ejb.ObjectNotFoundException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.CertificateCreationException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaSessionTest;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionTest;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpAliasConfiguration;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfigurationHolder;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfileException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CmpConfigAliasTest  extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CmpConfigAliasTest.class);
    private static final AuthenticationToken ADMIN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CmpConfigAliasTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private ConfigurationSessionRemote confSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private static final String issuerDN = "CN=TestCA";

    private int caid;
    private Certificate cacert;
    private CA testx509ca;
    
    private String baseResource = "publicweb/cmp/";
    private String httpReqPath;
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
     
        String httpServerPubHttp = confSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP);
        String CMP_HOST = confSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME);
        httpReqPath = "http://" + CMP_HOST + ":" + httpServerPubHttp + "/ejbca";
        
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaSessionTest.createTestX509CA(issuerDN, null, false, keyusage);
        caid = testx509ca.getCAId();
        cacert = testx509ca.getCACertificate();
        caSession.addCA(ADMIN, testx509ca);
        
        // Initialize config in here
        EjbcaConfigurationHolder.instance();

        confSession.backupConfiguration();

        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "TestCA");

    }
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();

        CryptoTokenManagementSessionTest.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(ADMIN, caid);
        
        boolean cleanUpOk = true;
        if (!confSession.restoreConfiguration()) {
            cleanUpOk = false;
        }
        assertTrue("Unable to clean up properly.", cleanUpOk);
    }

    

    /**
     * Tests the CMP URLs with configuration alias
     * @throws Exception
     */
    @Test
    public void test01Access() throws Exception {
        log.trace(">test01Access()");
        
        String urlString = httpReqPath + '/' + baseResource + "alias123"; 
        log.info("http URL: " + urlString);
        URL url = new URL(urlString);
        final HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-type", "application/pkixcmp");
        con.connect();
        assertEquals("Unexpected HTTP response code.", 200, con.getResponseCode()); // OK response
        
        urlString = httpReqPath + '/' + baseResource + "123"; 
        log.info("http URL: " + urlString);
        url = new URL(urlString);
        final HttpURLConnection con2 = (HttpURLConnection) url.openConnection();
        con2.setDoOutput(true);
        con2.setRequestMethod("POST");
        con2.setRequestProperty("Content-type", "application/pkixcmp");
        con2.connect();
        assertEquals("Unexpected HTTP response code.", 200, con2.getResponseCode()); // OK response
        
        urlString = httpReqPath + '/' + baseResource; 
        log.info("http URL: " + urlString);
        url = new URL(urlString);
        final HttpURLConnection con3 = (HttpURLConnection) url.openConnection();
        con3.setDoOutput(true);
        con3.setRequestMethod("POST");
        con3.setRequestProperty("Content-type", "application/pkixcmp");
        con3.connect();
        assertEquals("Unexpected HTTP response code.", 400, con3.getResponseCode()); // ERROR
        
        urlString = httpReqPath + '/' + baseResource + "??!!"; 
        log.info("http URL: " + urlString);
        url = new URL(urlString);
        final HttpURLConnection con4 = (HttpURLConnection) url.openConnection();
        con4.setDoOutput(true);
        con4.setRequestMethod("POST");
        con4.setRequestProperty("Content-type", "application/pkixcmp");
        con4.connect();
        assertEquals("Unexpected HTTP response code.", 400, con4.getResponseCode()); // ERROR
        
        log.trace("<test01Access()");
    }

    /**
     * Testing setting different CMP configuration both through an alias and without.
     * 
     * @throws Exception
     */
    @Test
    public void test02Configs() throws Exception {
        log.trace(">test02Configs()");
        
        String alias = "123";
        
        EjbcaConfigurationHolder.updateConfiguration("cmp." + alias + CmpAliasConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode(alias));
        
        EjbcaConfigurationHolder.updateConfiguration("cmp." + alias + CmpAliasConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode(alias));
        
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode(null));
        
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode(null));
        
        EjbcaConfigurationHolder.updateConfiguration("cmp.123.ra.namegenerationparameters", "CN");
        assertEquals("CN", CmpConfiguration.getRANameGenerationParameters(alias));
        
        log.trace("<test02Configs()");
    }
    
    /**
     * Sending a CRMF, Confirmation and Revocation request using a URL with configuration alias.
     * 
     * @throws Exception
     */
    @Test
    public void test03CMPReqs() throws Exception {
        log.trace(">test03CMPReqs()");
        
        String alias = "123";
        setDefaultConfigValues(alias);
        
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123");

        
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();
        String userDN = "CN=CmpAliasTestUser,C=SE";
        int reqid = 0;
        
        try {
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier( PKCSObjectIdentifiers.sha1WithRSAEncryption );
            
            PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
            assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
                
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, alias);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                    .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            reqid = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqid);
            assertNotNull("Crmf request did not return a certificate", cert);
        
            // ------------------- Send a CMP confirm message
            String hash = "foo123";
            PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, reqid);
            assertNotNull(confirm);
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(confirm);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, alias);
        
            //Since pAlg was not set in the ConfirmationRequest, the default DigestAlgorithm (SHA1) will be used
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpPKIConfirmMessage(userDN, cacert, resp);

            //-------------------------  Send a CMP revocation request
            PKIMessage rev = genRevReq(issuerDN, userDN, cert.getSerialNumber(), cacert, nonce, transid, true, pAlg, null);
            assertNotNull(rev);
            rev = protectPKIMessage(rev, false, "foo123", "mykeyid", 567);
            assertNotNull(rev);

            ByteArrayOutputStream baorev = new ByteArrayOutputStream();
            DEROutputStream outrev = new DEROutputStream(baorev);
            outrev.writeObject(rev);
            byte[] barev = baorev.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(barev, 200, alias);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
            assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
        
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, "CmpAliasTestUser", ReasonFlags.unused);
        }
        
        log.trace("<test03CMPReqs()");
    }

    /**
     * Sending a KeyUpdate request using a URL with configuration alias.
     * 
     * @throws Exception
     */
    @Test
    public void test04KeyUpdateRequest() throws Exception {
        log.trace(">test04KeyUpdateRequest()");
        
        String alias = "TestCA";
        
        setDefaultConfigValues(alias);
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_OPERATIONMODE, "normal");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY, "true");
        
        String username = "kuConfTestUser";
        String userDN = "CN=" + username + ",C=SE";
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();
        
        //--------------- create the user and issue his first certificate -----------------
        createUser(username, userDN, "foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = null;
        try {
            certificate = (X509Certificate) signSession.createCertificate(ADMIN, username, "foo123", keys.getPublic());
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

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage req = genRenewalReq(userDN, cacert, nonce, transid, keys, false, null, null, pAlg, new DEROctetString(nonce));
        assertNotNull("Failed to generate a CMP renewal request", req);
        CertReqMessages kur = (CertReqMessages) req.getBody().getContent();
        int reqId = kur.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        CMPCertificate extraCert = getCMPCert(certificate);
        req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(req);
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, alias);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkKurCertRepMessage(userDN, cacert, resp, reqId);
        assertNotNull("Failed to renew the certificate", cert);
        assertTrue("The new certificate's keys are incorrect.", cert.getPublicKey().equals(keys.getPublic()));
        
        log.trace("<test04KeyUpdateRequest()");
    }



    
    
    
    private void setDefaultConfigValues(String alias) {
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_RACANAME, "TestCA");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_DEFAULTCA, "TestCA");
        confSession.updateProperty(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_AUTHENTICATIONMODULE, "RegTokenPwd;HMAC");
        confSession.updateProperty(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-;-");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
        confSession.updateProperty("cmp.123.ra.namegenerationparameters", "CN");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + ".ra.namegenerationprefix", "");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + ".ra.namegenerationpostfix", "");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + ".ra.passwordgenparams", "random");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_RA_ALLOWCUSTOMCERTSERNO, "false");
        updatePropertyOnServer(CmpAliasConfiguration.CONFIG_PREFIX + alias + CmpAliasConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
    }
    
    private EndEntityInformation createUser(String username, String subjectDN, String password) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfileException, 
    WaitingForApprovalException, EjbcaException, Exception {

        EndEntityInformation user = new EndEntityInformation(username, subjectDN, caid, null, username+"@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            //endEntityManagementSession.addUser(ADMIN, user, true);
            endEntityManagementSession.addUser(ADMIN, username, password, subjectDN, "rfc822name=" + username + "@primekey.se", username + "@primekey.se",
                    true, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0,
                    caid);
            log.debug("created user: " + username);
        } catch (Exception e) {
            log.debug("User " + username + " already exists. Setting the user status to NEW");
            endEntityManagementSession.changeUser(ADMIN, user, true);
            endEntityManagementSession.setUserStatus(ADMIN, username, EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }

        return user;

    }

    private CMPCertificate getCMPCert(Certificate cert) throws CertificateEncodingException, IOException {
        ASN1InputStream ins = new ASN1InputStream(cert.getEncoded());
        ASN1Primitive pcert = ins.readObject();
        ins.close();
        org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate.getInstance(pcert.toASN1Primitive());
        return new CMPCertificate(c);
    }
    
    private byte[] sendCmpHttp(byte[] message, int httpRespCode, String alias) throws IOException, NoSuchProviderException {
        // POST the CMP request
        // we are going to do a POST
        
        final String urlString = getProperty("httpCmpProxyURL", httpReqPath + '/' + baseResource + alias);
        log.info("http URL: " + urlString);
        URL url = new URL(urlString);
        final HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-type", "application/pkixcmp");
        con.connect();
        // POST it
        OutputStream os = con.getOutputStream();
        os.write(message);
        os.close();

        assertEquals("Unexpected HTTP response code.", httpRespCode, con.getResponseCode());
        // Only try to read the response if we expected a 200 (ok) response
        if (httpRespCode == 200) {
            // Some appserver (Weblogic) responds with
            // "application/pkixcmp; charset=UTF-8"
            assertNotNull("No content type in response.", con.getContentType());
            assertTrue(con.getContentType().startsWith("application/pkixcmp"));
            // Check that the CMP respone has the cache-control headers as specified in 
            // http://tools.ietf.org/html/draft-ietf-pkix-cmp-transport-protocols-14
            final String cacheControl = con.getHeaderField("Cache-Control");
            assertNotNull(cacheControl);
            assertEquals("no-cache", cacheControl);
            final String pragma = con.getHeaderField("Pragma");
            assertNotNull(pragma);
            assertEquals("no-cache", pragma);
            // Now read in the bytes
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            // This works for small requests, and CMP requests are small enough
            InputStream in = con.getInputStream();
            int b = in.read();
            while (b != -1) {
                baos.write(b);
                b = in.read();
            }
            baos.flush();
            in.close();
            byte[] respBytes = baos.toByteArray();
            assertNotNull(respBytes);
            assertTrue(respBytes.length > 0);
            return respBytes;
        } else {
            return null;
        }
    }
    
    private X509Certificate checkKurCertRepMessage(String userDN, Certificate cacert, byte[] retMsg, int requestId) throws IOException,
    CertificateException {
        //
        // Parse response message
        //
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(retMsg));
        try {
            PKIMessage respObject = PKIMessage.getInstance(asn1InputStream.readObject());
            assertNotNull(respObject);
            PKIBody body = respObject.getBody();
            int tag = body.getType();
            assertEquals(8, tag);
            CertRepMessage c = (CertRepMessage) body.getContent();
            assertNotNull(c);
            CertResponse resp = c.getResponse()[0];
            assertNotNull(resp);
            assertEquals(resp.getCertReqId().getValue().intValue(), requestId);
            PKIStatusInfo info = resp.getStatus();
            assertNotNull(info);
            assertEquals(0, info.getStatus().intValue());
            CMPCertificate cmpcert = c.getCaPubs()[0]; //cc.getCertificate();
            assertNotNull(cmpcert);
            X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(cmpcert.getEncoded());
            X500Name name = new X500Name(CertTools.getSubjectDN(cert));
            checkDN(userDN, name);
            assertEquals(CertTools.stringToBCDNString(CertTools.getIssuerDN(cert)), CertTools.getSubjectDN(cacert));
            return cert;
        } finally {
            asn1InputStream.close();
        }
    }


    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
}
