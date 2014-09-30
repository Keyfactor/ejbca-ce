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
package org.cesecore.certificates.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaTestSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Basic vanilla tests for CrlCreateSession. Contains quite some code lifted from PublishingCrlSession that doesn't belong under the CESeCore
 * package. 
 * 
 * @version $Id$
 *
 */
public class CrlCreateSessionTest {

    private static final Logger log = Logger.getLogger(CrlCreateSessionTest.class);

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CaTestSessionRemote caTestSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CrlCreateSessionRemote crlCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlCreateSessionRemote.class);
    private CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final String className = CrlCreateSessionTest.class.getSimpleName();
    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(CrlCreateSessionTest.class.getSimpleName());

    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CaTestUtils.createX509Ca(authenticationToken, className, className, "CN="+className);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        CaTestUtils.removeCA(authenticationToken, className, className);
    }

    @Test
    public void createCrl() throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
        int caid = caSession.getCAInfo(authenticationToken, className).getCAId();
        CA ca = caTestSessionRemote.getCA(authenticationToken, caid);
        final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
        Collection<RevokedCertInfo> revcerts = certificateStoreSession.listRevokedCertInfo(certSubjectDN, -1);
        int fullnumber = crlStoreSession.getLastCRLNumber(certSubjectDN, false);
        int deltanumber = crlStoreSession.getLastCRLNumber(certSubjectDN, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;

        crlCreateSession.generateAndStoreCRL(authenticationToken, ca, revcerts, -1, nextCrlNumber);
        // We should now have a CRL generated
        byte[] crl = crlStoreSession.getLastCRL(ca.getSubjectDN(), false);
        try {
            assertNotNull(crl);
            // Check that it is signed by the correct public key
            X509CRL xcrl = CertTools.getCRLfromByteArray(crl);
            PublicKey pubK = ca.getCACertificate().getPublicKey();
            xcrl.verify(pubK);
        } catch (Exception e) {
            log.error("Error: ", e);
            fail("Should not throw here");
        } finally {
            // Remove it to clean database
            internalCertificateStoreSession.removeCRL(authenticationToken, CertTools.getFingerprintAsString(crl));
        }
    }

    
    @Test
    public void testCreateNewDeltaCRL() throws Exception {
        int caid = caSession.getCAInfo(authenticationToken, className).getCAId();
        CA ca = caTestSessionRemote.getCA(authenticationToken, caid);
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();
        cainfo.setDeltaCRLPeriod(1); // Issue very often..
        caSession.editCA(authenticationToken, cainfo);
        forceCRL(authenticationToken, ca);
        forceDeltaCRL(authenticationToken, ca);
    
        // Get number of last Delta CRL
        int number = crlStoreSession.getLastCRLNumber(ca.getSubjectDN(), true);
        log.debug("Last CRLNumber = " + number);
        byte[] crl = crlStoreSession.getLastCRL(ca.getSubjectDN(), true);
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        BigInteger num = CrlExtensions.getCrlNumber(x509crl);
        assertEquals(number, num.intValue());
        // Create a new CRL again to see that the number increases
        forceDeltaCRL(authenticationToken, ca);
        int number1 = crlStoreSession.getLastCRLNumber(ca.getSubjectDN(), true);
        assertEquals(number + 1, number1);
        byte[] crl1 = crlStoreSession.getLastCRL(ca.getSubjectDN(), true);
        X509CRL x509crl1 = CertTools.getCRLfromByteArray(crl1);
        BigInteger num1 = CrlExtensions.getCrlNumber(x509crl1);
        assertEquals(number + 1, num1.intValue());
        // Now create a normal CRL and a deltaCRL again. CRLNUmber should now be
        // increased by two
        forceCRL(authenticationToken, ca);
        forceDeltaCRL(authenticationToken, ca);
        int number2 = crlStoreSession.getLastCRLNumber(ca.getSubjectDN(), true);
        assertEquals(number1 + 2, number2);
        byte[] crl2 = crlStoreSession.getLastCRL(ca.getSubjectDN(), true);
        X509CRL x509crl2 = CertTools.getCRLfromByteArray(crl2);
        BigInteger num2 = CrlExtensions.getCrlNumber(x509crl2);
        assertEquals(number1 + 2, num2.intValue());
    }
    
    private void forceDeltaCRL(AuthenticationToken admin, CA ca) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CAOfflineException, CRLException {
        final CRLInfo crlInfo = crlStoreSession.getLastCRLInfo(ca.getSubjectDN(), false);
        // if no full CRL has been generated we can't create a delta CRL
        if (crlInfo != null) {
            CAInfo cainfo = ca.getCAInfo();
            if (cainfo.getDeltaCRLPeriod() > 0) {
                internalCreateDeltaCRL(admin, ca, crlInfo.getLastCRLNumber(), crlInfo.getCreateDate().getTime());   
            }
        } 
    }
    
    private String forceCRL(AuthenticationToken admin, CA ca) throws CAOfflineException, CryptoTokenOfflineException,
            AuthorizationDeniedException {
        if (ca == null) {
            throw new EJBException("No CA specified.");
        }
        CAInfo cainfo = ca.getCAInfo();
        String ret = null;

        final String caCertSubjectDN; // DN from the CA issuing the CRL to be used when searching for the CRL in the database.
        {
            final Collection<Certificate> certs = cainfo.getCertificateChain();
            final Certificate cacert = !certs.isEmpty() ? certs.iterator().next() : null;
            caCertSubjectDN = cacert != null ? CertTools.getSubjectDN(cacert) : null;
        }
        // We can not create a CRL for a CA that is waiting for certificate response
        if (caCertSubjectDN != null && cainfo.getStatus() == CAConstants.CA_ACTIVE) {
            long crlperiod = cainfo.getCRLPeriod();
            // Find all revoked certificates for a complete CRL

            Collection<RevokedCertInfo> revcerts = certificateStoreSession.listRevokedCertInfo(caCertSubjectDN, -1);
            Date now = new Date();
            Date check = new Date(now.getTime() - crlperiod);
            AuthenticationToken archiveAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrlCreateSession.archive_expired"));
            for (RevokedCertInfo data : revcerts) {
                // We want to include certificates that was revoked after the last CRL was issued, but before this one
                // so the revoked certs are included in ONE CRL at least. See RFC5280 section 3.3.
                if (data.getExpireDate().before(check)) {
                    // Certificate has expired, set status to archived in the database
                    if (log.isDebugEnabled()) {
                        log.debug("Archiving certificate with fp=" + data.getCertificateFingerprint() + ". Free memory="
                                + Runtime.getRuntime().freeMemory());
                    }
                    certificateStoreSession.setStatus(archiveAdmin, data.getCertificateFingerprint(), CertificateConstants.CERT_ARCHIVED);
                }
            }
            // a full CRL
            final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
            int fullnumber = crlStoreSession.getLastCRLNumber(certSubjectDN, false);
            int deltanumber = crlStoreSession.getLastCRLNumber(certSubjectDN, true);
            // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
            int nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;

            byte[] crlBytes = crlCreateSession.generateAndStoreCRL(admin, ca, revcerts, -1, nextCrlNumber);

            if (crlBytes != null) {
                ret = CertTools.getFingerprintAsString(crlBytes);
            }

        }

        return ret;
    }
    
    private byte[] internalCreateDeltaCRL(AuthenticationToken admin, CA ca, int baseCrlNumber, long baseCrlCreateTime)
            throws CryptoTokenOfflineException, CAOfflineException, AuthorizationDeniedException, CRLException {
        byte[] crlBytes = null;
        CAInfo cainfo = ca.getCAInfo();
        final String caCertSubjectDN;
        {
            final Collection<Certificate> certs = cainfo.getCertificateChain();
            final Certificate cacert = !certs.isEmpty() ? certs.iterator().next() : null;
            caCertSubjectDN = cacert != null ? CertTools.getSubjectDN(cacert) : null;
        }

        if ((baseCrlNumber == -1) && (baseCrlCreateTime == -1)) {
            CRLInfo basecrlinfo = crlStoreSession.getLastCRLInfo(caCertSubjectDN, false);
            baseCrlCreateTime = basecrlinfo.getCreateDate().getTime();
            baseCrlNumber = basecrlinfo.getLastCRLNumber();
        }
        // Find all revoked certificates
        Collection<RevokedCertInfo> revcertinfos = certificateStoreSession.listRevokedCertInfo(caCertSubjectDN, baseCrlCreateTime);
        if (log.isDebugEnabled()) {
            log.debug("Found " + revcertinfos.size() + " revoked certificates.");
        }
        // Go through them and create a CRL, at the same time archive expired certificates
        ArrayList<RevokedCertInfo> certs = new ArrayList<RevokedCertInfo>();
        Iterator<RevokedCertInfo> iter = revcertinfos.iterator();
        while (iter.hasNext()) {
            RevokedCertInfo ci = iter.next();
            if (ci.getRevocationDate() == null) {
                ci.setRevocationDate(new Date());
            }
            certs.add(ci);
        }
        // create a delta CRL
        final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
        int fullnumber = crlStoreSession.getLastCRLNumber(certSubjectDN, false);
        int deltanumber = crlStoreSession.getLastCRLNumber(certSubjectDN, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;

        crlBytes = crlCreateSession.generateAndStoreCRL(admin, ca, certs, baseCrlNumber, nextCrlNumber);
        X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
        if (log.isDebugEnabled()) {
            log.debug("Created delta CRL with expire date: " + crl.getNextUpdate());
        }

        return crlBytes;
    }

}
