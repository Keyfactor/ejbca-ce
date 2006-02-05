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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;

import javax.ejb.DuplicateKeyException;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.protocol.ocsp.FnrFromUnidExtension;
import org.ejbca.util.CertTools;

/** Tests http pages of ocsp lookup server.
 * This test requires a lot of setup. 
 * - The lookup service must be active
 * - There must be a database for the unid-fnr mapping
 * - You must have a CA that has issued certificates with serialNumber in the DN matching the unid
 * - You should have four certificates:
 * - You also need a keystore issued by the CA for TLS communication, the keystore cert must be configured in the lookup extension as trusted
 *    - /lookup-kstrust.p12 (password lookup)
 * - You also need a keystore as above but not configured as trusted in the lookup extension
 *    - /lookup-ksnotrust.p12 (password lookup)
 **/
public class ProtocolLookupServerHttpTest extends TestCase {
    private static Logger log = Logger.getLogger(ProtocolLookupServerHttpTest.class);

    private final String httpReqPath;
    private final String resourceOcsp;


    private static Context ctx;
    private static ISignSessionHome home;
    private static ISignSessionRemote remote;
    protected ICertificateStoreSessionHome storehome;
    private static IUserAdminSessionRemote usersession;
    protected static int caid = 0;
    protected static Admin admin;
    private static X509Certificate cacert = null;
    private static KeyStore kstrust = null;
    private static KeyStore ksnotrust = null;


    public ProtocolLookupServerHttpTest(String name)  throws Exception {
        this(name,"http://127.0.0.1:8080/ejbca", "publicweb/status/ocsp");
    }

    public ProtocolLookupServerHttpTest(String name, String reqP, String res) throws Exception {
        super(name);
        httpReqPath = reqP;
        resourceOcsp = res;

        // Install BouncyCastle provider
        CertTools.installBCProvider();
        
        try {
			kstrust = KeyStore.getInstance("PKCS12", "BC");
			FileInputStream fis = new FileInputStream("/lookup-kstrust.p12");
			kstrust.load(fis, "lookup".toCharArray());
			fis.close();
			ksnotrust = KeyStore.getInstance("PKCS12", "BC");
			fis = new FileInputStream("/lookup-ksnotrust.p12");
			ksnotrust.load(fis, "lookup".toCharArray());
			fis.close();
		} catch (Exception e) {
			log.error("Exception during construction: ", e);
			//assertTrue(e.getMessage(), false);
		}
        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);

        ctx = getInitialContext();
        Object obj = ctx.lookup("CAAdminSession");
        ICAAdminSessionHome cahome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ICAAdminSessionHome.class);
        ICAAdminSessionRemote casession = cahome.create();
        setCAID(casession);
        CAInfo cainfo = casession.getCAInfo(admin, caid);
        Collection certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator certiter = certs.iterator();
            cacert = (X509Certificate) certiter.next();
        } else {
            log.error("NO CACERT for caid " + caid);
        }
        obj = ctx.lookup("RSASignSession");
        home = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ISignSessionHome.class);
        remote = home.create();
        Object obj2 = ctx.lookup("CertificateStoreSession");
        storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
        obj = ctx.lookup("UserAdminSession");
        IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        usersession = userhome.create();


    }

    protected void setCAID(ICAAdminSessionRemote casession) throws RemoteException {
        Collection caids = casession.getAvailableCAs(admin);
        Iterator iter = caids.iterator();
        if (iter.hasNext()) {
            caid = ((Integer) iter.next()).intValue();
        } else {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
    }
    protected void setUp() throws Exception {
        log.debug(">setUp()");

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
    
    /**
     * Generates a RSA key pair.
     *
     * @return KeyPair the generated key pair
     *
     * @throws Exception if en error occurs...
     */
    private static KeyPair genKeys() throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(512);
        log.debug("Generating keys, please wait...");
        KeyPair rsaKeys = keygen.generateKeyPair();
        log.debug("Generated " + rsaKeys.getPrivate().getAlgorithm() + " keys with length" +
                ((RSAPrivateKey) rsaKeys.getPrivate()).getModulus().bitLength());
        return rsaKeys;
    } // genKeys

    /** Tests ocsp message with good status and a valid unid
     * @throws Exception error
     */
    public void test01OcspGoodWithFnr() throws Exception {

        // Make user that we know...
        boolean userExists = false;
        try {
            usersession.addUser(admin,"unidtest","foo123","C=SE,O=AnaTom,surname=Jansson,serialNumber=123456789,CN=UNIDTest",null,"unidtest@anatom.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: unidtest, foo123, C=SE, O=AnaTom,surname=Jansson,serialNumber=123456789, CN=UNIDTest");
        } catch (RemoteException re) {
            if (re.detail instanceof DuplicateKeyException) {
                userExists = true;
            }
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }

        if (userExists) {
            log.debug("User unidtest already exists.");
            usersession.changeUser(admin, "unidtest", "foo123", "C=SE,O=AnaTom,surname=Jansson,serialNumber=123456789,CN=UNIDTest",null,"unidtest@anatom.se",false, SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,UserDataConstants.STATUS_NEW, caid);
            //usersession.setUserStatus(admin,"ocsptest",UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        // Generate certificate for the new user
        KeyPair keys = genKeys();

        // user that we know exists...
        X509Certificate ocspTestCert = (X509Certificate) remote.createCertificate(admin, "unidtest", "foo123", keys.getPublic());
        assertNotNull("Misslyckades skapa cert", ocspTestCert);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        Hashtable exts = new Hashtable();
        X509Extension ext = new X509Extension(false, new DEROctetString(new FnrFromUnidExtension("123456789")));
        exts.put(FnrFromUnidExtension.FnrFromUnidOid, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a singleResponse
        SingleResp singleResp = sendOCSPPost(req.getEncoded());
        
        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /** Tests ocsp message with good status and invalid unid
     * @throws Exception error
     */
    public void test02OcspGoodWithNoFnr() throws Exception {
    }

    /** Tests ocsp message with good status but no serialNnumber in the DN
     * @throws Exception error
     */
    public void test03OcspGoodNoSerialNo() throws Exception {
    }

    /** test a lookup request with regular http, should not work
     * 
     * @throws Exception
     */
    public void test04HttpNotAuthorized() throws Exception {
    }

    /** test a lookup message from an untrusted requestor, shoudl not work
     * 
     * @throws Exception
     */
    public void test05HttpsNotAuthorized() throws Exception {
    }
    //
    // Private helper methods
    //
    
    private SingleResp sendOCSPPost(byte[] ocspPackage) throws IOException, OCSPException, NoSuchProviderException {
        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceOcsp);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = con.getOutputStream();
        os.write(ocspPackage);
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", "application/ocsp-response", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and OCSP requests are small
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(respBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        X509Certificate[] chain = brep.getCerts("BC");
        boolean verify = brep.verify(chain[0].getPublicKey(), "BC");
        assertTrue("Response failed to verify.", verify);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps shoudl be 1.", singleResps.length, 1);
        SingleResp singleResp = singleResps[0];
        return singleResp;
    }
}
