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
package org.ejbca.core.ejb.authentication.web;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.ejbca.core.model.InternalEjbcaResources;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the WebAuthenticationProviderSessionBean
 * 
 * @version $Id$
 *
 */
public class WebAuthenticationProviderSessionBeanTest {

    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private final CertificateStoreSessionRemote certificateStoreSession = JndiHelper.getRemoteSession(CertificateStoreSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = JndiHelper
            .getRemoteSession(InternalCertificateStoreSessionRemote.class);
    private final SecurityEventsAuditorSessionRemote securityEventsAuditorSession = JndiHelper
            .getRemoteSession(SecurityEventsAuditorSessionRemote.class);
    private final WebAuthenticationProviderProxySessionRemote authenticationProviderProxy = JndiHelper
            .getRemoteSession(WebAuthenticationProviderProxySessionRemote.class);

    private static KeyPair keys;

    private final TestAlwaysAllowLocalAuthenticationToken internalToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            WebAuthenticationProviderSessionBeanTest.class.getSimpleName()));

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    @Test
    public void testAuthenticateWithCertificateExpired() throws Exception {
        X509Certificate certificate = CertTools.genSelfCert("CN=Foo", -1, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
        AuthenticationToken authenticationToken = authenticationProviderProxy.authenticate(subject);
        assertNull("Authentication was returned for expired cert", authenticationToken);
        final String expectedRegexp = intres.getLocalizedMessage("authentication.certexpired", ".*", ".*");
        //Examine the last log entry
        for (final String logDeviceId : securityEventsAuditorSession.getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> list = securityEventsAuditorSession.selectAuditLogs(internalToken, 0, 0,
                    QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())), logDeviceId);
            Map<Object, Object> details = list.get(list.size() - 1).getMapAdditionalDetails();
            String msg = (String) details.get("msg");
            assertTrue("Incorrect log message was produced. (Was: <" + msg + ">. Expected to match: <" + expectedRegexp + ">",
                    msg.matches(expectedRegexp));
        }
    }

    @Test
    public void testAuthenticationWithFutureCertificate() throws Exception {
        X509Certificate certificate = generateUnbornCert("CN=foo", null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
        AuthenticationToken authenticationToken = authenticationProviderProxy.authenticate(subject);
        assertNull("Authentication was returned for unborn cert", authenticationToken);
        final String expectedRegexp = intres.getLocalizedMessage("authentication.certexpired", ".*", ".*");
        //Examine the last log entry
        for (final String logDeviceId : securityEventsAuditorSession.getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> list = securityEventsAuditorSession.selectAuditLogs(internalToken, 0, 0,
                    QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())), logDeviceId);
            Map<Object, Object> details = list.get(list.size() - 1).getMapAdditionalDetails();
            String msg = (String) details.get("msg");
            assertTrue("Incorrect log message was produced. (Was: <" + msg + ">. Expected to match: <" + expectedRegexp + ">",
                    msg.matches(expectedRegexp));
        }
    }

    @Test
    public void testAuthenticationWithMissingCertificate() throws Exception {
        X509Certificate certificate = CertTools.genSelfCert("CN=Foo", 1, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
        AuthenticationToken authenticationToken = authenticationProviderProxy.authenticate(subject);
        assertNull("Authentication was returned for missing cert", authenticationToken);
        final String expectedRegexp = intres.getLocalizedMessage("authentication.revokedormissing", ".*");
        //Examine the last log entry
        for (final String logDeviceId : securityEventsAuditorSession.getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> list = securityEventsAuditorSession.selectAuditLogs(internalToken, 0, 0,
                    QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())), logDeviceId);
            Map<Object, Object> details = list.get(list.size() - 1).getMapAdditionalDetails();
            String msg = (String) details.get("msg");
            assertTrue("Incorrect log message was produced. (Was: <" + msg + ">. Expected to match: <" + expectedRegexp + ">",
                    msg.matches(expectedRegexp));
        }
    }

    @Test
    public void testAuthenticationWithInactiveCertificate() throws Exception {
        X509Certificate certificate = CertTools.genSelfCert("CN=Foo", 1, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
        try {
            //We're using CertificateConstants.CERT_REVOKED here, but any status but any status != CertificateConstants.CERT_ACTIVE would suffice.
            certificateStoreSession.storeCertificate(internalToken, certificate, "foo", "1234", CertificateConstants.CERT_REVOKED,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, "footag", new Date().getTime());
            AuthenticationToken authenticationToken = authenticationProviderProxy.authenticate(subject);
            assertNull("Authentication was returned for inactive cert", authenticationToken);
            final String expectedRegexp = intres.getLocalizedMessage("authentication.revokedormissing", ".*");
            //Examine the last log entry
            for (final String logDeviceId : securityEventsAuditorSession.getQuerySupportingLogDevices()) {
                final List<? extends AuditLogEntry> list = securityEventsAuditorSession.selectAuditLogs(internalToken, 0, 0,
                        QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())), logDeviceId);
                Map<Object, Object> details = list.get(list.size() - 1).getMapAdditionalDetails();
                String msg = (String) details.get("msg");
                assertTrue("Incorrect log message was produced. (Was: <" + msg + ">. Expected to match: <" + expectedRegexp + ">",
                        msg.matches(expectedRegexp));
            }
        } finally {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
    }

    /*
     * Code nastily stolen from CertTools.genSelfCertForPurpose
     */
    private static X509Certificate generateUnbornCert(String dn, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException, IllegalStateException,
            NoSuchProviderException {
        int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        // Create self signed certificate
        Date firstDate = new Date();
        // Set starting date to tomorrow
        firstDate.setTime(firstDate.getTime() + (24 * 3600 * 1000));
        Date lastDate = new Date();
        // Set Expiry in two days
        lastDate.setTime(lastDate.getTime() + ((2 * 24 * 60 * 60 * 1000)));

        X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();

        // Transform the PublicKey to be sure we have it in a format that the X509 certificate generator handles, it might be
        // a CVC public key that is passed as parameter
        PublicKey publicKey = null;
        if (pubKey instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pubKey;
            RSAPublicKeySpec rSAPublicKeySpec = new RSAPublicKeySpec(rsapk.getModulus(), rsapk.getPublicExponent());
            try {
                publicKey = KeyFactory.getInstance("RSA").generatePublic(rSAPublicKeySpec);
            } catch (InvalidKeySpecException e) {
                publicKey = pubKey;
            }
        } else if (pubKey instanceof ECPublicKey) {
            ECPublicKey ecpk = (ECPublicKey) pubKey;
            try {
                ECPublicKeySpec ecspec = new ECPublicKeySpec(ecpk.getW(), ecpk.getParams()); // will throw NPE if key is "implicitlyCA"
                publicKey = KeyFactory.getInstance("EC").generatePublic(ecspec);
            } catch (InvalidKeySpecException e) {
                publicKey = pubKey;
            } catch (NullPointerException e) {
                publicKey = pubKey;
            }
        } else {
            publicKey = pubKey;
        }
        // Serialnumber is random bits, where random generator is initialized with Date.getTime() when this
        // bean is created.
        byte[] serno = new byte[8];
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new Date().getTime());
        random.nextBytes(serno);
        certgen.setSerialNumber(new java.math.BigInteger(serno).abs());
        certgen.setNotBefore(firstDate);
        certgen.setNotAfter(lastDate);
        certgen.setSignatureAlgorithm(sigAlg);
        certgen.setSubjectDN(CertTools.stringToBcX509Name(dn));
        certgen.setIssuerDN(CertTools.stringToBcX509Name(dn));
        certgen.setPublicKey(publicKey);
        // Basic constranits is always critical and MUST be present at-least in CA-certificates.
        BasicConstraints bc = new BasicConstraints(isCA);
        certgen.addExtension(X509Extensions.BasicConstraints.getId(), true, bc);
        // Put critical KeyUsage in CA-certificates
        if (isCA) {
            X509KeyUsage ku = new X509KeyUsage(keyusage);
            certgen.addExtension(X509Extensions.KeyUsage.getId(), true, ku);
        }
        // Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Firefox.
        try {
            if (isCA) {
                SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(
                        publicKey.getEncoded())).readObject());
                SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);

                SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(
                        publicKey.getEncoded())).readObject());
                AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);

                certgen.addExtension(X509Extensions.SubjectKeyIdentifier.getId(), false, ski);
                certgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), false, aki);
            }
        } catch (IOException e) { // do nothing
        }
        // CertificatePolicies extension if supplied policy ID, always non-critical
        if (policyId != null) {
            PolicyInformation pi = new PolicyInformation(new DERObjectIdentifier(policyId));
            DERSequence seq = new DERSequence(pi);
            certgen.addExtension(X509Extensions.CertificatePolicies.getId(), false, seq);
        }
        X509Certificate selfcert = certgen.generate(privKey, "BC");
        return selfcert;
    }

}
