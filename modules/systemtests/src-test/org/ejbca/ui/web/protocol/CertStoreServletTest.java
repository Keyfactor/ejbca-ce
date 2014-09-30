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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.mail.MessagingException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Testing of CertStoreServlet
 * 
 * @version $Id$
 * 
 */
public class CertStoreServletTest extends CaTestCase {
    private final static Logger log = Logger.getLogger(CertStoreServletTest.class);
    
    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
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
    
    
    /**
     * @throws MessagingException
     * @throws URISyntaxException
     * @throws IOException
     * @throws CertificateException
     * @throws MalformedURLException
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     * @throws InvalidAlgorithmException 
     * @throws CryptoTokenAuthenticationFailedException 
     * @throws CryptoTokenOfflineException 
     * @throws CAExistsException 
     */

    @Test
    public void testIt() throws MalformedURLException, CertificateException, IOException, URISyntaxException, MessagingException,
            CADoesntExistsException, AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        final CAInHierarchy ca1 = new CAInHierarchy("root", this);
        final CAInHierarchy ca1_1 = new CAInHierarchy("1 from root", this);
        ca1.subs.add(ca1_1);
        final CAInHierarchy ca2_1 = new CAInHierarchy("2 from root at" + new Date(), this);
        ca1.subs.add(ca2_1);
        final CAInHierarchy ca1_1_1 = new CAInHierarchy("1 from 1 from root", this);
        ca1_1.subs.add(ca1_1_1);
        final CAInHierarchy ca2_1_1 = new CAInHierarchy("2 from 1 from root at " + new Date(), this);
        ca1_1.subs.add(ca2_1_1);
        final CAInHierarchy ca3_1_1 = new CAInHierarchy("3 from 1 from root", this);
        ca1_1.subs.add(ca3_1_1);
        try {
            final Set<Integer> setOfSubjectKeyIDs = new HashSet<Integer>();
            final X509Certificate rootCert = ca1.createCA(setOfSubjectKeyIDs);
            log.info("The number of CAs created was " + setOfSubjectKeyIDs.size() + ".");
            internalCertificateStoreSession.reloadCaCertificateCache();
            new CertFetchAndVerify().doIt(rootCert, setOfSubjectKeyIDs);
            assertEquals("All created CA certificates not found.", 0, setOfSubjectKeyIDs.size());
        } finally {
            ca1.deleteCA();
        }
    }
    @Test
    public void testDisplayPage() throws MalformedURLException, IOException, URISyntaxException {
        final String sURI = CertFetchAndVerify.getURL();
        log.debug("URL: '"+sURI+"'.");
        final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
        connection.connect();
        Assert.assertTrue( "Fetching CRL with '"+sURI+"' is not working.", HttpURLConnection.HTTP_OK==connection.getResponseCode() );
        {
            final Map<String, List<String>> mheaders = connection.getHeaderFields();
            Assert.assertNotNull(mheaders);
            final StringWriter sw = new StringWriter();
            final PrintWriter pw = new PrintWriter(sw);
            pw.println("Header of page with valid links to certificates");
            for ( Entry<String, List<String>> e : mheaders.entrySet() ) {
                Assert.assertNotNull(e);
                Assert.assertNotNull(e.getValue());
                pw.println("\t"+e.getKey());
                for ( String s : e.getValue()) {
                    pw.println("\t\t"+s);
                }
            }
            pw.close();
            log.debug(sw);
        }
        Assert.assertEquals("text/html;charset=UTF-8", connection.getContentType());
    }
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
}

class CAInHierarchy {
    private final static AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertStoreServletTest"));
    final String name;
    final Set<CAInHierarchy> subs;
    final CaTestCase testCase;

    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    CAInHierarchy(String _name, CaTestCase _testCase) {
        this.name = _name;
        this.subs = new HashSet<CAInHierarchy>();
        this.testCase = _testCase;
    }

    X509Certificate createCA(Set<Integer> setOfSubjectKeyIDs) throws CADoesntExistsException, AuthorizationDeniedException, CAExistsException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        return createCA(CAInfo.SELFSIGNED, null, setOfSubjectKeyIDs);
    }

    private X509Certificate createCA(int signedBy, Collection<Certificate> certificateChain, Set<Integer> setOfSubjectKeyIDs)
            throws CADoesntExistsException, AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        Assert.assertTrue("Failed to created certificate.",
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

    void deleteCA() throws CADoesntExistsException, AuthorizationDeniedException {
        final Iterator<CAInHierarchy> i = this.subs.iterator();
        while (i.hasNext()) {
            i.next().deleteCA();
        }
        CaTestCase.removeTestCA(this.name);
        internalCertificateStoreSession.removeCertificatesBySubject("CN=" + this.name + ",O=EJBCA junit,OU=CertStoreServletTest");
    }

    private CAInfo getCAInfo() throws CADoesntExistsException, AuthorizationDeniedException {
        return this.testCase.getCAInfo(admin, this.name);
    }
}
