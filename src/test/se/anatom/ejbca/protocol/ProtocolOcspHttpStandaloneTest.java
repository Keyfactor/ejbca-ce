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

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.CreateException;

import junit.framework.TestSuite;

import org.apache.log4j.Logger;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateDataPK;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.util.CertTools;

/** Tests http pages of ocsp
 **/
public class ProtocolOcspHttpStandaloneTest extends ProtocolOcspHttpTest {
    private static Logger log = Logger.getLogger(ProtocolOcspHttpStandaloneTest.class);

    public static void main(String args[]) {
        junit.textui.TestRunner.run(suite());
    }


    public static TestSuite suite() {
        return new TestSuite(ProtocolOcspHttpStandaloneTest.class);
    }


    public ProtocolOcspHttpStandaloneTest(String name) {
        super(name, "http://larslap.mine.nu:8080/ejbca", "publicweb/status/ocsp");
    }

    protected void setCAID(ICAAdminSessionRemote casession) {
        caid = 1584670546;
    }
    
    public void test01Access() throws Exception {
        super.test01Access();
    }

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test02OcspGood() throws Exception {
        log.debug(">test02OcspGood()");

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        final X509Certificate ocspTestCert = getTestCert(false);
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        OCSPReq req = gen.generate();

        // Send the request and receive a singleResponse
        SingleResp singleResp = sendOCSPPost(req.getEncoded(), null);
        
        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
        log.debug("<test02OcspGood()");
    }
    private X509Certificate getTestCert( boolean isRevoked ) throws RemoteException, CreateException {
        ICertificateStoreSessionRemote store = storehome.create();
        Collection certs = store.findCertificatesByUsername(admin, "ocspTest");
        Iterator i = certs.iterator();
        while ( i.hasNext() ) {
            X509Certificate cert = (X509Certificate)i.next();
            if ( isRevoked==(store.isRevoked(admin, cert.getIssuerDN().toString(), cert.getSerialNumber()).getReason()!=RevokedCertInfo.NOT_REVOKED) )
                return cert;
        }
        assertNotNull("Misslyckades hämta cert", null);
        return null;
    }

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test03OcspRevoked() throws Exception {
        log.debug(">test03OcspRevoked()");
        // Now revoke the certificate and try again
        CertificateDataPK pk = new CertificateDataPK();
        final X509Certificate ocspTestCert = getTestCert(true);
        pk.fingerprint = CertTools.getFingerprintAsString(ocspTestCert);
        ICertificateStoreSessionRemote store = storehome.create();
        store.revokeCertificate(admin, ocspTestCert,null,RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        OCSPReq req = gen.generate();

        // Send the request and receive a singleResponse
        SingleResp singleResp = sendOCSPPost(req.getEncoded(), null);

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
        RevokedStatus rev = (RevokedStatus) status;
        assertTrue("Status does not have reason", rev.hasRevocationReason());
        int reason = rev.getRevocationReason();
        assertEquals("Wrong revocation reason", reason, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        log.debug("<test03OcspRevoked()");
    }

}
