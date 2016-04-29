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
package org.ejbca.core.ejb.authentication.web;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

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
import java.security.cert.CertificateException;
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

import javax.ejb.CreateException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
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

    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final SecurityEventsAuditorSessionRemote securityEventsAuditorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SecurityEventsAuditorSessionRemote.class);
    private final WebAuthenticationProviderProxySessionRemote authenticationProviderProxy = EjbRemoteHelper.INSTANCE.getRemoteSession(WebAuthenticationProviderProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static KeyPair keys;

    private final TestAlwaysAllowLocalAuthenticationToken internalToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            WebAuthenticationProviderSessionBeanTest.class.getSimpleName()));

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    /**
     * Regression test. Makes sure that CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION
     * is considered a valid state as well. 
     * 
     */
    @Test
    public void testAuthenticateWithNotifiedAboutExpiration() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IllegalStateException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException, CreateException, AuthorizationDeniedException  {
        X509Certificate certificate = CertTools.genSelfCert("CN=Foo", 1, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
        try {
            certificateStoreSession.storeCertificateRemote(internalToken, EJBTools.wrap(certificate), "foo", "1234", CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityInformation.NO_ENDENTITYPROFILE, "footag", new Date().getTime());
            AuthenticationToken authenticationToken = authenticationProviderProxy.authenticate(subject);
            assertNotNull("Authentication was not returned for active (but soon to expire) cert", authenticationToken);
        } finally {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
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
                    QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())).add(Criteria.orderAsc("sequenceNumber")), logDeviceId);
            Map<String, Object> details = list.get(list.size() - 1).getMapAdditionalDetails();
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
                    QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())).add(Criteria.orderAsc("sequenceNumber")), logDeviceId);
            Map<String, Object> details = list.get(list.size() - 1).getMapAdditionalDetails();
            String msg = (String) details.get("msg");
            assertTrue("Incorrect log message was produced. (Was: <" + msg + ">. Expected to match: <" + expectedRegexp + ">",
                    msg.matches(expectedRegexp));
        }
    }

    @Test
    public void testAuthenticationWithMissingCertificate() throws Exception {
        String requireAdminCertificateInDatabase = null;
        try {
            requireAdminCertificateInDatabase = configurationSession.getProperty(WebConfiguration.CONFIG_REQCERTINDB);
            configurationSession.updateProperty(WebConfiguration.CONFIG_REQCERTINDB, Boolean.TRUE.toString());
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
                        QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())).add(Criteria.orderAsc("sequenceNumber")), logDeviceId);
                Map<String, Object> details = list.get(list.size() - 1).getMapAdditionalDetails();
                String msg = (String) details.get("msg");
                assertTrue("Incorrect log message was produced. (Was: <" + msg + ">. Expected to match: <" + expectedRegexp + ">",
                        msg.matches(expectedRegexp));
            }
        } finally {
            configurationSession.updateProperty(WebConfiguration.CONFIG_REQCERTINDB, requireAdminCertificateInDatabase);
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
            certificateStoreSession.storeCertificateRemote(internalToken, EJBTools.wrap(certificate), "foo", "1234", CertificateConstants.CERT_REVOKED,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityInformation.NO_ENDENTITYPROFILE, "footag", new Date().getTime());
            AuthenticationToken authenticationToken = authenticationProviderProxy.authenticate(subject);
            assertNull("Authentication was returned for inactive cert", authenticationToken);
            final String expectedRegexp = intres.getLocalizedMessage("authentication.revokedormissing", ".*");
            //Examine the last log entry
            for (final String logDeviceId : securityEventsAuditorSession.getQuerySupportingLogDevices()) {
                final List<? extends AuditLogEntry> list = securityEventsAuditorSession.selectAuditLogs(internalToken, 0, 0,
                        QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())).add(Criteria.orderAsc("sequenceNumber")), logDeviceId);
                Map<String, Object> details = list.get(list.size() - 1).getMapAdditionalDetails();
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
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IllegalStateException,
            NoSuchProviderException, OperatorCreationException, CertificateException, IOException {
        int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        // Create self signed certificate
        Date firstDate = new Date();
        // Set starting date to tomorrow
        firstDate.setTime(firstDate.getTime() + (24 * 3600 * 1000));
        Date lastDate = new Date();
        // Set Expiry in two days
        lastDate.setTime(lastDate.getTime() + ((2 * 24 * 60 * 60 * 1000)));

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
        
        final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance((ASN1Sequence)ASN1Primitive.fromByteArray(publicKey.getEncoded()));                
        X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(dn), new java.math.BigInteger(serno).abs(), firstDate, 
                lastDate, CertTools.stringToBcX500Name(dn), pkinfo);
        // Basic constranits is always critical and MUST be present at-least in CA-certificates.
        BasicConstraints bc = new BasicConstraints(isCA);
        certbuilder.addExtension(Extension.basicConstraints, true, bc);
        
        // Put critical KeyUsage in CA-certificates
        if (isCA) {
            X509KeyUsage ku = new X509KeyUsage(keyusage);
            certbuilder.addExtension(Extension.keyUsage, true, ku);
        }
        // Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Firefox.
        try {
            if (isCA) {
                JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
                SubjectKeyIdentifier ski = extensionUtils.createSubjectKeyIdentifier(pubKey);
                AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(publicKey);
                certbuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
                certbuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
            }
        } catch (IOException e) { // do nothing
        }
        // CertificatePolicies extension if supplied policy ID, always non-critical
        if (policyId != null) {
            PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier(policyId));
            DERSequence seq = new DERSequence(pi);
            certbuilder.addExtension(Extension.certificatePolicies, false, seq);
        }
        final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(
                BouncyCastleProvider.PROVIDER_NAME).build(privKey), 20480);
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        final X509Certificate selfcert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
    
        return selfcert;
    }

}
