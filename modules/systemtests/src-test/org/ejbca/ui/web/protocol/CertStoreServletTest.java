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

package org.ejbca.ui.web.protocol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


/**
 * Testing of CertStoreServlet
 * 
 * 
 */
public class CertStoreServletTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(CertStoreServletTest.class);
    
    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CertificateProfileSessionRemote certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);

    @Override
    @Before
    public void setUp() throws Exception{
        super.setUp();
    }
    
    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }
    
    private String enrollSubCa(int caId) throws Exception {
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
        int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);

        EndEntityInformation user = new EndEntityInformation("subCaEe", "CN=subCaEe", caId, null,
                "subca@subCaEe.ee", new EndEntityType(EndEntityTypes.ENDUSER), 0, cpId, EndEntityConstants.TOKEN_USERGEN, null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setPassword("foo123");

        KeyPair keys = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
        X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
        X509Certificate cert = (X509Certificate) resp.getCertificate();
        assertNotNull("Failed to create certificate", cert);
        String fingerprint = CertTools.getFingerprintAsString(cert);

        // Check that the cert got created in the database
        Certificate cert1 = certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert));
        assertNotNull(cert1);
        assertEquals(fingerprint, CertTools.getFingerprintAsString(cert1));
        assertTrue(CertTools.isCA(cert1));
        return fingerprint;
    }
    
    @Test
    public void testIt() throws Exception {
        final CAInHierarchy ca1 = new CAInHierarchy("root", this);
        final CAInHierarchy ca11 = new CAInHierarchy("1 from root", this);
        ca1.subs.add(ca11);
        final CAInHierarchy ca21 = new CAInHierarchy("2 from root at" + new Date(), this);
        ca1.subs.add(ca21);
        final CAInHierarchy ca111 = new CAInHierarchy("1 from 1 from root", this);
        ca11.subs.add(ca111);
        final CAInHierarchy ca211 = new CAInHierarchy("2 from 1 from root at " + new Date(), this);
        ca11.subs.add(ca211);
        final CAInHierarchy ca311 = new CAInHierarchy("3 from 1 from root", this);
        ca11.subs.add(ca311);
        String fingerprint = null;
        try {
            final Set<Integer> setOfSubjectKeyIDs = new HashSet<>();
            final X509Certificate rootCert = ca1.createCA(setOfSubjectKeyIDs);
            fingerprint = enrollSubCa(ca1.getCAInfo().getCAId());
            log.info("The number of CAs created was " + setOfSubjectKeyIDs.size() + ".");
            internalCertificateStoreSession.reloadCaCertificateCache();
            List<CertificateDataWrapper>  wrappedCaCacheEntries = internalCertificateStoreSession.getCaCertificateCacheEntries();
            List<X509Certificate> caCacheEntries = new ArrayList<>();
            wrappedCaCacheEntries.forEach(x -> caCacheEntries.add((X509Certificate) x.getCertificate()));
            int matchFound = 0;
            for (X509Certificate cert: caCacheEntries) {
                if(setOfSubjectKeyIDs.contains(HashID.getFromKeyID(cert).getKey())) {
                    matchFound++;
                }
                if(CertTools.getFingerprintAsString(cert).equalsIgnoreCase(fingerprint)) {
                    fail("SubCa enrolled as EE should not be cached.");
                }
            }
            assertEquals("All created CA certificates not found in cache.", setOfSubjectKeyIDs.size(), matchFound);
            new CertFetchAndVerify().doIt(rootCert, setOfSubjectKeyIDs);
            assertEquals("All created CA certificates not found.", setOfSubjectKeyIDs.size(), 0);
        } finally {
            certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
            internalCertificateStoreSession.removeCertificate(fingerprint);
            ca1.deleteCA();
        }
    }

    @Test
    public void testDisplayPage() throws IOException, URISyntaxException {
        final String sURI = CertFetchAndVerify.getURL();
        log.debug("URL: '"+sURI+"'.");
        final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
        connection.connect();
        Assert.assertTrue( "Fetching CRL with '"+sURI+"' is not working.", HttpURLConnection.HTTP_OK==connection.getResponseCode() );
        displayPage(connection);
        assertEquals("text/html;charset=UTF-8", connection.getContentType());
    }

    private void displayPage(final HttpURLConnection connection) {
        final Map<String, List<String>> mheaders = connection.getHeaderFields();
        Assert.assertNotNull(mheaders);
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw);
        pw.println("Header of page with valid links to certificates");
        for (Entry<String, List<String>> e : mheaders.entrySet()) {
            Assert.assertNotNull(e);
            Assert.assertNotNull(e.getValue());
            pw.println("\t" + e.getKey());
            for (String s : e.getValue()) {
                pw.println("\t\t" + s);
            }
        }
        pw.close();
        log.debug(sw);

    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
}

class CAInHierarchy {
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertStoreServletTest"));
    private final String name;
    final Set<CAInHierarchy> subs;
    private final CaTestCase testCase;

    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    CAInHierarchy(final String name, final CaTestCase testCase) {
        this.name = name;
        this.subs = new HashSet<>();
        this.testCase = testCase;
    }

    X509Certificate createCA(Set<Integer> setOfSubjectKeyIDs) throws Exception {
        return createCA(CAInfo.SELFSIGNED, null, setOfSubjectKeyIDs);
    }

    private X509Certificate createCA(int signedBy, Collection<Certificate> certificateChain, Set<Integer> setOfSubjectKeyIDs)
            throws Exception {
        assertTrue("Failed to created certificate.",
                CaTestCase.createTestCA(this.name, 1024, "CN=" + this.name + ",O=EJBCA junit,OU=CertStoreServletTest", signedBy, certificateChain));
        final CAInfo info = getCAInfo();
        final Collection<Certificate> newCertificateChain = info.getCertificateChain();
        final X509Certificate caCert = (X509Certificate) newCertificateChain.iterator().next();
        setOfSubjectKeyIDs.add(HashID.getFromKeyID(caCert).getKey());
        final Iterator<CAInHierarchy> i = this.subs.iterator();
        final int caid = info.getCAId();
        while (i.hasNext()) {
            i.next().createCA(caid, newCertificateChain, setOfSubjectKeyIDs);
        }
        return caCert;
    }

    void deleteCA() throws AuthorizationDeniedException {
        for (CAInHierarchy sub : this.subs) {
            sub.deleteCA();
        }
        CaTestCase.removeTestCA(this.name);
        internalCertificateStoreSession.removeCertificatesBySubject("CN=" + this.name + ",O=EJBCA junit,OU=CertStoreServletTest");
    }

    CAInfo getCAInfo() throws CADoesntExistsException, AuthorizationDeniedException {
        return this.testCase.getCAInfo(admin, this.name);
    }
}
