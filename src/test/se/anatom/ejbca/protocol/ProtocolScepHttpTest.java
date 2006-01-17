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

package se.anatom.ejbca.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.DuplicateKeyException;
import javax.ejb.FinderException;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.ocsp.OCSPException;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.core.protocol.ScepRequestMessage;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.HttpUnitOptions;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;

/** Tests http pages of ocsp and scep
 **/
public class ProtocolScepHttpTest extends TestCase {
    private static Logger log = Logger.getLogger(TestMessages.class);

    private static final String httpReqPath = "http://127.0.0.1:8080/ejbca";
    private static final String resourceScep = "publicweb/apply/scep/pkiclient.exe";
    private static final String resourceScepNoCA = "publicweb/apply/scep/noca/pkiclient.exe";

    static byte[] openscep = Base64.decode(("MIIGqwYJKoZIhvcNAQcCoIIGnDCCBpgCAQExDjAMBggqhkiG9w0CBQUAMIICuwYJ" +
            "KoZIhvcNAQcBoIICrASCAqgwggKkBgkqhkiG9w0BBwOgggKVMIICkQIBADGB1TCB" +
            "0gIBADA7MC8xDzANBgNVBAMTBlRlc3RDQTEPMA0GA1UEChMGQW5hVG9tMQswCQYD" +
            "VQQGEwJTRQIIbzEhUVZYO3gwDQYJKoZIhvcNAQEBBQAEgYCksIoSXYsCQPot2DDW" +
            "dexdFqLj1Fuz3xSpu/rLozXKxEY0n0W0JXRR9OxxuyqNw9cLZhiyWkNsJGbP/rEz" +
            "yrXe9NXuLK5U8+qqE8OhnY9BhCxjeUJSLni6oCSi7YzwOqdg2KmifJrQQI/jZIiC" +
            "tSISAtE6qi6DKQwLCkQLmokLrjCCAbIGCSqGSIb3DQEHATARBgUrDgMCBwQILYvZ" +
            "rBWuC02AggGQW9o5MB/7LN4o9G4ZD1l2mHzS+g+Y/dT2qD/qIaQi1Mamv2oKx9eO" +
            "uFtaGkBBGWZlIKg4mm/DFtvXqW8Y5ijAiQVHHPuRKNyIV6WVuFjNjhNlM+DWLJR+" +
            "rpHEhvB6XeDo/pd+TyOKFcxedMPTD7U+j46yd46vKdmoKAiIF21R888uVSz3GDts" +
            "NlqgvZ7VlaI++Tj7aPdOI7JTdQXZk2FWF7Ql0LBIPwk9keffptF5if5Y+aHqB0a2" +
            "uQj1aE8Em15VG8p8MmLJOX0OA1aeqfxR0wk343r44UebliY2DE8cEnym/fmya30/" +
            "7WYzJ7erWofO2ukg1yc93wUpyIKxt2RGIy5geqQCjCYSSGgaNFafEV2pnOVSx+7N" +
            "9z/ICNQfDBD6b83MO7yPHC1cXcdREKHHeqaKyQLiVRk9+R/3D4vEZt682GRaUKOY" +
            "PQXK1Be2nyZoo4gZs62nZVAliJ+chFkEUog9k9OsIvZRG7X+VEjVYBqxlE1S3ikt" +
            "igFXiuLC/LDCi3IgVwQjfNx1/mhxsO7GSaCCAfswggH3MIIBYKADAgEDAiA4OEUy" +
            "REVFNDcwNjhCQjM3RjE5QkE2NDdCRjAyRkQwRjANBgkqhkiG9w0BAQQFADAyMQsw" +
            "CQYDVQQGEwJTZTERMA8GA1UEChMIUHJpbWVLZXkxEDAOBgNVBAMTB1RvbWFzIEcw" +
            "HhcNMDMwNjAxMDgzNDQyWhcNMDMwNzAxMDgzNDQyWjAyMQswCQYDVQQGEwJTZTER" +
            "MA8GA1UEChMIUHJpbWVLZXkxEDAOBgNVBAMTB1RvbWFzIEcwgZ8wDQYJKoZIhvcN" +
            "AQEBBQADgY0AMIGJAoGBAOu47fpIQfzfSnEBTG2WJpKZz1891YLNulc7XgMk8hl3" +
            "nVC4m34SaR7eXR3nCsorYEpPPmL3affaPFsBnNBQNoZLxKmQ1RKiDyu8dj90AKCP" +
            "CFlIM2aJbKMiQad+dt45qse6k0yTrY3Yx0hMH76tRkDif4DjM5JUvdf4d/zlYcCz" +
            "AgMBAAEwDQYJKoZIhvcNAQEEBQADgYEAGNoWI02kXNEA5sPHb3KEY8QZoYM5Kha1" +
            "JA7HLmlXKy6geeJmk329CUnvF0Cr7zxbMkFRdUDUtR8omDDnGlBSOCkV6LLYH939" +
            "Z8iysfaxigZkxUqUYGLtYHhsEjVgcpfKZVxTz0E2ocR2P+IuU04Duel/gU4My6Qv" +
            "LDpwo1CQC10xggHDMIIBvwIBATBWMDIxCzAJBgNVBAYTAlNlMREwDwYDVQQKEwhQ" +
            "cmltZUtleTEQMA4GA1UEAxMHVG9tYXMgRwIgODhFMkRFRTQ3MDY4QkIzN0YxOUJB" +
            "NjQ3QkYwMkZEMEYwDAYIKoZIhvcNAgUFAKCBwTASBgpghkgBhvhFAQkCMQQTAjE5" +
            "MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTAzMDYw" +
            "MTA4MzQ0MlowHwYJKoZIhvcNAQkEMRIEEBqGJFo7n4B8sFBCi54PckIwIAYKYIZI" +
            "AYb4RQEJBTESBBA77Owxh2rbflhXsDYw3xsLMDAGCmCGSAGG+EUBCQcxIhMgODhF" +
            "MkRFRTQ3MDY4QkIzN0YxOUJBNjQ3QkYwMkZEMEYwDQYJKoZIhvcNAQEBBQAEgYB4" +
            "BPcw4NPIt4nMOFKSGg5oM1nGDPGFN7eorZV+/2uWiQfdtK4B4lzCTuNxWRT853dW" +
            "dRDzXBCGEArlG8ef+vDD/HP9SX3MQ0NJWym48VI9bTpP/mJlUKSsfgDYHohvUlVI" +
            "E5QFC6ILVLUmuWPGchUEAb8t30DDnmeXs8QxdqHfbQ==").getBytes());

    private static Context ctx;
    private static IUserAdminSessionRemote usersession;
    private static int caid = 0;
    private static Admin admin;
    private static X509Certificate cacert = null;
    private static KeyPair keys = null;
    private static String caname = null;
    private String transId = null;
    private String senderNonce = null;

    public static void main(String args[]) {
        junit.textui.TestRunner.run(suite());
    }


    public static TestSuite suite() {
        return new TestSuite(ProtocolScepHttpTest.class);
    }


    public ProtocolScepHttpTest(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");

        // Install BouncyCastle provider
        CertTools.installBCProvider();

        // We want to get error responses without exceptions
        HttpUnitOptions.setExceptionsThrownOnErrorStatus(false);

        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);

        ctx = getInitialContext();
        Object obj = ctx.lookup("CAAdminSession");
        ICAAdminSessionHome cahome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ICAAdminSessionHome.class);
        ICAAdminSessionRemote casession = cahome.create();
        Collection caids = casession.getAvailableCAs(admin);
        Iterator iter = caids.iterator();
        if (iter.hasNext()) {
            caid = ((Integer) iter.next()).intValue();
        } else {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        CAInfo cainfo = casession.getCAInfo(admin, caid);
        caname = cainfo.getName();
        Collection certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator certiter = certs.iterator();
            X509Certificate cert = (X509Certificate) certiter.next();
            // Make sure we have a BC certificate
            cacert = CertTools.getCertfromByteArray(cert.getEncoded());
        } else {
            log.error("NO CACERT for caid " + caid);
        }
        obj = ctx.lookup("UserAdminSession");
        IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        usersession = userhome.create();

        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        log.debug(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        log.debug("<getInitialContext");
        return ctx;
    }
 
    public void test01Access() throws Exception {
        WebConversation wc = new WebConversation();
        // Hit scep, gives a 400: Bad Request
        WebRequest request = new GetMethodWebRequest(httpReqPath + '/' + resourceScep);
        WebResponse response = wc.getResponse(request);
        assertEquals("Response code", 400, response.getResponseCode());
    }

    /** Tests a random old scep message from OpenScep
     * @throws Exception error
     */
    public void test02OpenScep() throws Exception {
        log.debug(">test02OpenScep()");
        // send message to server and see what happens
        WebConversation wc = new WebConversation();
        WebRequest request = new GetMethodWebRequest(httpReqPath + '/' + resourceScep);
        request.setParameter("operation", "PKIOperation");
        request.setParameter("message", new String(Base64.encode(openscep)));
        WebResponse response = wc.getResponse(request);
        // TODO: since our request most certainly uses the wrong CA cert to encrypt the
        // request, it will fail. If we get something back, we came a little bit at least :)
        // We should get a NOT_FOUND error back.
        assertEquals("Response code", 404, response.getResponseCode());
        log.debug("<test02OpenScep()");
    }

    public void test03ScepRequestOKSHA1() throws Exception {
        log.debug(">test03ScepRequestOKSHA1()");
        // find a CA create a user and
        // send SCEP req to server and get good response with cert

        // Make user that we know...
        createScepUser();
        
        // Pre-generate key for all requests to speed things up a bit
        keys = KeyTools.genKeys(512);
        byte[] msgBytes = genScepRequest(false, CMSSignedDataGenerator.DIGEST_SHA1);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes, false);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, "C=SE,O=PrimeKey,CN=sceptest", senderNonce, transId, false, CMSSignedDataGenerator.DIGEST_SHA1, false);
        log.debug("<test03ScepRequestOKSHA1()");
    }

    public void test04ScepRequestOKMD5() throws Exception {
        log.debug(">test04ScepRequestOKMD5()");
        // find a CA create a user and
        // send SCEP req to server and get good response with cert

        // Make user that we know...
        createScepUser();
        
        // Pre-generate key for all requests to speed things up a bit
        keys = KeyTools.genKeys(512);
        byte[] msgBytes = genScepRequest(false, CMSSignedDataGenerator.DIGEST_MD5);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes, false);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, "C=SE,O=PrimeKey,CN=sceptest", senderNonce, transId, false, CMSSignedDataGenerator.DIGEST_MD5, false);
        log.debug("<test04ScepRequestOKMD5()");
    }

    public void test05ScepRequestPostOK() throws Exception {
        log.debug(">test05ScepRequestPostOK()");
        // find a CA, create a user and
        // send SCEP req to server and get good response with cert

        createScepUser();
        
        byte[] msgBytes = genScepRequest(false, CMSSignedDataGenerator.DIGEST_SHA1);
        // Send message with GET
        byte[] retMsg = sendScep(true, msgBytes, false);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, "C=SE,O=PrimeKey,CN=sceptest", senderNonce, transId, false, CMSSignedDataGenerator.DIGEST_SHA1, false);
        log.debug(">test05ScepRequestPostOK()");
    }

    public void test06ScepRequestPostOKNoCA() throws Exception {
        log.debug(">test06ScepRequestPostOKNoCA()");
        // find a CA, create a user and
        // send SCEP req to server and get good response with cert

        createScepUser();
        
        byte[] msgBytes = genScepRequest(false, CMSSignedDataGenerator.DIGEST_SHA1);
        // Send message with GET
        byte[] retMsg = sendScep(true, msgBytes, true);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, "C=SE,O=PrimeKey,CN=sceptest", senderNonce, transId, false, CMSSignedDataGenerator.DIGEST_SHA1, true);
        log.debug(">test06ScepRequestPostOKNoCA()");
    }

    public void test07ScepGetCACert() throws Exception {
        log.debug(">test07ScepGetCACert()");
        String reqUrl = httpReqPath + '/' + resourceScep+"?operation=GetCACert&message="+caname;
        URL url = new URL(reqUrl);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", "application/x-x509-ca-cert", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        InputStream in = con.getInputStream();
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
        X509Certificate cert = CertTools.getCertfromByteArray(respBytes);
        // Check that we got the right cert back
        assertEquals(cacert.getSubjectDN().getName(), cert.getSubjectDN().getName());
        log.debug(">test07ScepGetCACert()");
    }

    public void test08ScepGetCrl() throws Exception {
        log.debug(">test08ScepGetCrl()");
        byte[] msgBytes = genScepRequest(true, CMSSignedDataGenerator.DIGEST_SHA1);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes, false);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, "C=SE,O=PrimeKey,CN=sceptest", senderNonce, transId, true, CMSSignedDataGenerator.DIGEST_SHA1, false);
        log.debug(">test08ScepGetCrl()");
    }
    public void test09ScepGetCACaps() throws Exception {
        log.debug(">test09ScepGetCACaps()");
        String reqUrl = httpReqPath + '/' + resourceScep+"?operation=GetCACaps&message="+caname;
        URL url = new URL(reqUrl);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", "text/plain", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        InputStream in = con.getInputStream();
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
        assertEquals(new String(respBytes), "POSTPKIOperation\nSHA-1");
        log.debug(">test09ScepGetCACaps()");
    }
    public void test99CleanUp() throws Exception {
        // remove user
        usersession.deleteUser(admin,"sceptest");
        log.debug("deleted user: sceptest");
    }
    
    //
    // Private helper methods
    //
    private void createScepUser() throws RemoteException, AuthorizationDeniedException, FinderException, UserDoesntFullfillEndEntityProfile {
        // Make user that we know...
        boolean userExists = false;
        try {
            usersession.addUser(admin,"sceptest","foo123","C=SE,O=PrimeKey,CN=sceptest",null,"ocsptest@anatom.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: sceptest, foo123, C=SE, O=PrimeKey, CN=sceptest");
        } catch (RemoteException re) {
            if (re.detail instanceof DuplicateKeyException) {
                userExists = true;
            }
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }

        if (userExists) {
            log.debug("User sceptest already exists.");
            usersession.setUserStatus(admin,"sceptest",UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        
    }

    private byte[] genScepRequest(boolean makeCrlReq, String digestoid) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidAlgorithmParameterException, CertStoreException, IOException, CMSException {
        ScepRequestGenerator gen = new ScepRequestGenerator();
        gen.setKeys(keys);
        gen.setDigestOid(digestoid);
        byte[] msgBytes = null;
        if (makeCrlReq) {
            msgBytes = gen.generateCrlReq("C=SE, O=PrimeKey, CN=sceptest", cacert);
        } else {
            msgBytes = gen.generateCertReq("C=SE, O=PrimeKey, CN=sceptest", "foo123", cacert);            
        }
        assertNotNull(msgBytes);
        transId = gen.getTransactionId();
        assertNotNull(transId);
        byte[] idBytes = Base64.decode(transId.getBytes());
        assertTrue(idBytes.length == 16);
        senderNonce = gen.getSenderNonce();
        byte[] nonceBytes = Base64.decode(senderNonce.getBytes());
        assertTrue(nonceBytes.length == 16); 
        return msgBytes;
    }
    
    private void checkScepResponse(byte[] retMsg, String userDN, String senderNonce, String transId, boolean crlRep, String digestOid, boolean noca) throws CMSException, NoSuchProviderException, NoSuchAlgorithmException, CertStoreException, InvalidKeyException, CertificateException, SignatureException, CRLException {
        //
        // Parse response message
        //
        CMSSignedData s = new CMSSignedData(retMsg);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        Collection col = signers.getSigners();
        assertTrue(col.size() > 0);
        Iterator iter = col.iterator();
        SignerInformation signerInfo = (SignerInformation)iter.next();
        // Check that the message is signed with the correct digest alg
        assertEquals(signerInfo.getDigestAlgOID(), digestOid);
        SignerId sinfo = signerInfo.getSID();
        // Check that the signer is the expected CA
        assertEquals(CertTools.stringToBCDNString(cacert.getIssuerDN().getName()), CertTools.stringToBCDNString(sinfo.getIssuerAsString()));
        // Verify the signature
        signerInfo.verify(cacert.getPublicKey(), "BC");
        // Get authenticated attributes
        AttributeTable tab = signerInfo.getSignedAttributes();
        // --Fail info
        Attribute attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_failInfo));
        // No failInfo on this success message
        assertNull(attr); 
        // --Message type
        attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_messageType));
        assertNotNull(attr);
        ASN1Set values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        DERString str = DERPrintableString.getInstance((values.getObjectAt(0)));
        String messageType = str.getString();
        assertEquals("3", messageType);
        // --Success status
        attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_pkiStatus));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = DERPrintableString.getInstance((values.getObjectAt(0)));
        assertEquals(ResponseStatus.SUCCESS.getValue(), str.getString());
        // --SenderNonce
        attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_senderNonce));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        ASN1OctetString octstr = ASN1OctetString.getInstance(values.getObjectAt(0));
        // SenderNonce is something the server came up with, but it should be 16 chars
        assertTrue(octstr.getOctets().length == 16);
        // --Recipient Nonce
        attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_recipientNonce));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        octstr = ASN1OctetString.getInstance(values.getObjectAt(0));
        // recipient nonce should be the same as we sent away as sender nonce
        assertEquals(senderNonce, new String(Base64.encode(octstr.getOctets())));
        // --Transaction ID
        attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_transId));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = DERPrintableString.getInstance((values.getObjectAt(0)));
        // transid should be the same as the one we sent
        assertEquals(transId, str.getString());
        
        //
        // Check different message types
        //
        if (messageType.equals("3")) {
            // First we extract the encrypted data from the CMS enveloped data contained
            // within the CMS signed data
            CMSProcessable sp = s.getSignedContent();
            byte[] content = (byte[])sp.getContent();
            CMSEnvelopedData ed = new CMSEnvelopedData(content);
            RecipientInformationStore recipients = ed.getRecipientInfos();
            Collection c = recipients.getRecipients();
            assertEquals(c.size(), 1);
            Iterator it = c.iterator();
            byte[] decBytes = null;
            RecipientInformation recipient = (RecipientInformation) it.next();
            decBytes = recipient.getContent(keys.getPrivate(), "BC");
            // This is yet another CMS signed data
            CMSSignedData sd = new CMSSignedData(decBytes);
            // Get certificates from the signed data
            CertStore certstore = sd.getCertificatesAndCRLs("Collection","BC");
            if (crlRep) {
                // We got a reply with a requested CRL
                Collection crls = certstore.getCRLs(null);
                assertEquals(crls.size(), 1);
                it = crls.iterator();
                X509CRL retCrl = null;
                // CRL is first (and only)
                retCrl = (X509CRL)it.next();
                System.out.println("Got CRL with DN: "+ retCrl.getIssuerDN().getName());
//                try {
//                    FileOutputStream fos = new FileOutputStream("sceptest.der");
//                    fos.write(retCrl.getEncoded());
//                    fos.close();
//                } catch (Exception e) {}
                // check the returned CRL
                assertEquals(cacert.getSubjectDN().getName(), retCrl.getIssuerDN().getName());
                retCrl.verify(cacert.getPublicKey());
            } else {
                // We got a reply with a requested certificate 
                Collection certs = certstore.getCertificates(null);
                // EJBCA returns the issued cert and the CA cert (cisco vpn client requires that the ca cert is included)
                if (noca) {
                    assertEquals(certs.size(), 1);	                	
                } else {
                    assertEquals(certs.size(), 2);                	
                }
                it = certs.iterator();
                // Issued certificate must be first
                boolean verified = false;
                boolean gotcacert = false;
                String mysubjectdn = CertTools.stringToBCDNString("C=SE,O=PrimeKey,CN=sceptest");
                while (it.hasNext()) {
                    X509Certificate retcert = (X509Certificate)it.next();
                    System.out.println("Got cert with DN: "+ retcert.getSubjectDN().getName());
//                    try {
//                        FileOutputStream fos = new FileOutputStream("sceptest.der");
//                        fos.write(retcert.getEncoded());
//                        fos.close();
//                    } catch (Exception e) {}
                
                    // check the returned certificate
                    String subjectdn = CertTools.stringToBCDNString(retcert.getSubjectDN().getName());
                    if (mysubjectdn.equals(subjectdn)) {
                        // issued certificate
                        assertEquals(CertTools.stringToBCDNString("C=SE,O=PrimeKey,CN=sceptest"), subjectdn);
                        retcert.verify(cacert.getPublicKey());
                        assertTrue(checkKeys(keys.getPrivate(), retcert.getPublicKey()));
                        verified = true;
                    } else {
                        // ca certificate
                        assertEquals(cacert.getSubjectDN().getName(), retcert.getIssuerDN().getName());
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
    private byte[] sendScep(boolean post, byte[] scepPackage, boolean noca) throws IOException, OCSPException, NoSuchProviderException {
        // POST the OCSP request
        // we are going to do a POST
    	String resource = resourceScep;
    	if (noca) {
    		resource = resourceScepNoCA;
    	}
    	String urlString = httpReqPath + '/' + resource+"?operation=PKIOperation";
    	log.debug("UrlString =" + urlString);
        HttpURLConnection con = null;
        if (post) {
            URL url = new URL(urlString);
            con = (HttpURLConnection)url.openConnection();
            con.setDoOutput(true);
            con.setRequestMethod("POST");
            con.connect();
            // POST it
            OutputStream os = con.getOutputStream();
            os.write(scepPackage);
            os.close();
        } else {
            String reqUrl = urlString + "&message=" + URLEncoder.encode(new String(Base64.encode(scepPackage)),"UTF-8");
            URL url = new URL(reqUrl);
            con = (HttpURLConnection)url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
        }

        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", "application/x-pki-message", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        InputStream in = con.getInputStream();
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

}
