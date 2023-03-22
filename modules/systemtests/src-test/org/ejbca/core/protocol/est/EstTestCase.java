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

package org.ejbca.core.protocol.est;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.provider.X509TrustManagerAcceptAll;
import org.ejbca.config.EstConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;

import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CertTools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Helper class for EST Junit tests. 
 * You can run this test against a EST Proxy instead of direct to the CA by setting the system property httpEstProxyURL, 
 * for example to "https://ra-host:8442/.well-known/est"
 */
public abstract class EstTestCase extends CaTestCase {

    private static final Logger log = Logger.getLogger(EstTestCase.class);

    protected static final String CP_NAME = "EST_TEST_CP_NAME";
    protected static final String EEP_NAME = "EST_TEST_EEP_NAME";
    protected int eepId;
    protected int cpId;
    private static final String SUPER_ADMINISTRATOR_ROLE_NAME = "Super Administrator Role";
    private static final String MULTIPART_MIXED_CONTENT_BOUNDARY = "CONTENTBOUNDARY";

    protected final String httpsPubReqPath; // = "https://127.0.0.1:8442/.well-known/est/";
    protected final String httpsPrivReqPath; // = "https://127.0.0.1:8443/.well-known/est/";
    private final String EST_HOST; // = "127.0.0.1";

    protected final CertificateStoreSession certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    protected final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    protected final EndEntityManagementSession endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    protected final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    protected final CertificateProfileSession certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    protected final EndEntityProfileSession endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    protected final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);            
    protected final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    protected final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);

    protected final static AuthenticationToken ADMIN = new TestAlwaysAllowLocalAuthenticationToken("EstTestCase");

    /** Keystore used for TLS client authentication, which is used for EST simplereenroll and RA mode with client cert authentication */ 
    private static KeyStore CLIENT_KEYSTORE;
    private static final String KEY_STORE_PASSWORD = "changeit";
    private static final String LOGIN_STORE_PATH = System.getProperty("java.io.tmpdir") + File.separator + "esttestuser_" + new Date().getTime() + ".jks";

    public EstTestCase() {
        final String httpServerPubHttps = SystemTestsConfiguration.getRemotePortHttps(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTPS));
        final String httpServerPrivHttps = SystemTestsConfiguration.getRemotePortHttps(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERPRIVHTTPS));
        this.EST_HOST = SystemTestsConfiguration.getRemoteHost(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        this.httpsPubReqPath = "https://" + this.EST_HOST + ":" + httpServerPubHttps + "/.well-known/est/";
        this.httpsPrivReqPath = "https://" + this.EST_HOST + ":" + httpServerPrivHttps + "/.well-known/est/";
    }
    
    @Override
    protected void setUp() throws Exception { // NOPMD: this is a test base class
        super.setUp();
        cleanup();
        // Configure a Certificate profile (CmpRA) using ENDUSER as template and
        // check "Allow validity override".
        this.cpId = addCertificateProfile(CP_NAME);
        this.eepId = addEndEntityProfile(EEP_NAME, this.cpId);
    } 
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        cleanup();
    }
    
    private void cleanup() throws AuthorizationDeniedException {
        endEntityProfileSession.removeEndEntityProfile(ADMIN, EEP_NAME);
        certProfileSession.removeCertificateProfile(ADMIN, CP_NAME);
    }


    
    /**
     * Adds a certificate profile for end entities.
     * 
     * @param name the name.
     * @return the id of the newly created certificate profile.
     */
    protected final int addCertificateProfile(final String name) {
        assertTrue("Certificate profile with name " + name + " already exists. Clear test data first.", this.certProfileSession.getCertificateProfile(name) == null);
        final CertificateProfile result = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        int id = -1;
        try {
            this.certProfileSession.addCertificateProfile(ADMIN, name, result);
            id = this.certProfileSession.getCertificateProfileId(name);
            log.info("Certificate profile '" + name + "' and id " + id + " created.");
        } catch (AuthorizationDeniedException | CertificateProfileExistsException e) {
            log.error(e.getMessage(), e);
            fail(e.getMessage());
        }
        return id;
    }
    
    /**
     * Adds an end entity profile and links it with the default certificate profile for test {@link EndEntityProfile#setDefaultCertificateProfile(int)}.
     * 
     * @param name the name of the end entity profile.
     * @param certificateProfileId the default certificate profiles ID.
     * @return the ID of the newly created end entity profile. 
     */
    protected final int addEndEntityProfile(final String name, final int certificateProfileId) {
        assertTrue("End entity profile with name " + name + " already exists. Clear test data first.", this.endEntityProfileSession.getEndEntityProfile(name)  == null);
        final EndEntityProfile result = new EndEntityProfile(true);
        result.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certificateProfileId));
        int id = 0;
        try {
            this.endEntityProfileSession.addEndEntityProfile(ADMIN,name, result);
            id = this.endEntityProfileSession.getEndEntityProfileId(name);
        } catch (AuthorizationDeniedException | EndEntityProfileExistsException | EndEntityProfileNotFoundException e) {
            log.error(e.getMessage(), e);
            fail(e.getMessage());
        }
        return id;
    }
        
    class SimpleVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    /**
     * Sends a EST request with the alias requestAlias in the URL and expects a HTTP response
     *
     * @param the EST message to send, can be null if the request has no message bytes
     * @param estAlias the alias that is specified in the URL
     * @param operation the EST operation, i.e. cacerts, simpleenroll, simplereenroll, etc
     * @param expectedReturnCode the HTTP return code that we expect for this request, i.e. success vs failure
     * @param expectedErrMsg the error message returned when expectedReturnCode is not OK, f.ex "<html><head><title>Error</title></head><body>No client certificate supplied</body></html>"
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     * @throws Exception if connection to server can not be established
     */
    protected byte[] sendEstRequest(final String estAlias, final String operation, final byte[] message, final int expectedReturnCode, final String expectedErrMsg) throws IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
        return sendEstRequest(estAlias, operation, message, expectedReturnCode, expectedErrMsg, null, null);
    }
    
    /**
     * Sends a EST request with the alias requestAlias in the URL and expects a HTTP response
     *
     * @param the EST message to send, can be null if the request has no message bytes
     * @param estAlias the alias that is specified in the URL
     * @param operation the EST operation, i.e. cacerts, simpleenroll, simplereenroll, etc
     * @param expectedReturnCode the HTTP return code that we expect for this request, i.e. success (200) vs failure (f.ex 401 Unauthorized)
     * @param expectedErrMsg the error message returned when expectedReturnCode is not OK, f.ex "<html><head><title>Error</title></head><body>No client certificate supplied</body></html>"
     * @param username for basic authentication, if null no basic auth header will be added
     * @param password for basic authentication
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     * @throws Exception if connection to server can not be established
     */
    protected byte[] sendEstRequest(final String estAlias, final String operation, final byte[] message, final int expectedReturnCode, final String expectedErrMsg, final String username, final String password) throws IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
        return sendEstRequest(false, estAlias, operation, message, expectedReturnCode, expectedErrMsg, username, password);
    }
    protected byte[] sendEstRequest(final boolean useTLSClientCert, final String estAlias, final String operation, final byte[] message, final int expectedReturnCode, final String expectedErrMsg, final String username, final String password) throws IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
        // POST the ESTrequest (URL can be set in systemtests.properties, and overridden by system property)
        final String urlString;
        if (useTLSClientCert) {
            urlString = getProperty("httpEstClientCertProxyURL", this.httpsPrivReqPath) + estAlias + '/' + operation;            
        } else {
            urlString = getProperty("httpEstNoClientCertProxyURL", this.httpsPubReqPath) + estAlias + '/' + operation;
        }
        log.info("http URL: " + urlString);
        final URL url = new URL(urlString);

        // Create TLS context that accepts all CA certificates and does not use client cert authentication
        final SSLContext context = SSLContext.getInstance("TLS");
        final TrustManager[] tm = new X509TrustManager[] {new X509TrustManagerAcceptAll()};
        final KeyManager[] km;
        if (useTLSClientCert) {
            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(CLIENT_KEYSTORE, KEY_STORE_PASSWORD.toCharArray());
            km = keyManagerFactory.getKeyManagers();            
        } else {
            km = null;
        }
        context.init(km, tm, new SecureRandom());

        SSLSocketFactory factory = context.getSocketFactory();
        HttpsURLConnection.setDefaultSSLSocketFactory(factory);

        final HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setHostnameVerifier(new SimpleVerifier()); // no hostname verification for testing
        if (username != null) {
            final String auth = username + ":" + password;
            final String authHeader = "Basic " + Base64.toBase64String(auth.getBytes(StandardCharsets.UTF_8));
            log.info("Using basic authentication with: " + username + ":" + password);
            con.setRequestProperty("Authorization", authHeader);
        }
        con.setDoOutput(true);
        if (operation.contains("simple")) {
            // mime-type for simpleenroll and simplereenroll as specified in RFC7030 section 3.2.4 and 4.2.1
            con.setRequestProperty("Content-type", "application/pkcs10");
            con.setRequestMethod("POST");
        } else {
            con.setRequestMethod("GET"); // cacerts uses GET, Content-type is N/A according to RFC7030 section 3.2.4
        }
        con.setRequestProperty("Content-type", "application/est");
        con.connect();
        // POST the message if there is one
        if (message != null) {
            final OutputStream os = con.getOutputStream();
            os.write(message);
            os.close();
        }

        // Read response bytes, it can be an error message from the server as well
        ByteArrayOutputStream errbaos = new ByteArrayOutputStream();
        if (con.getResponseCode() != HttpServletResponse.SC_OK) {
            // This works for small requests, and EST requests are small enough
            InputStream in = con.getErrorStream();
            int b = in.read();
            while (b != -1) {
                errbaos.write(b);
                b = in.read();
            }
            errbaos.flush();
            in.close();
        }
        byte[] errBytes = errbaos.toByteArray();
        // EST alias does not exist: 400 bad request
        // Unknown operation: 404 not found
        // Invalid credentials: 401 unauthorized
        // OK: 200
        assertEquals("Unexpected HTTP response code: " + new String(errBytes) + ".", expectedReturnCode, con.getResponseCode());
        // Only try to read the response if we expected a 200 (ok) response
        if (expectedReturnCode != 200) {
            assertEquals("Error message was not the expected", expectedErrMsg, new String(errBytes));
            return null;
        }
        // Check returned headers as specified in RFC7030 section 3.2.4
        assertNotNull("No content type in response.", con.getContentType());
        if(!operation.equalsIgnoreCase("serverkeygen")) {
            assertTrue("Unexpected response Content-type: " + con.getContentType(), con.getContentType().startsWith("application/pkcs7-mime"));
        } else {
            assertTrue("Unexpected response for serverkeygen Content-type: " + con.getContentType(), con.getContentType().startsWith("multipart/mixed ; boundary=" + MULTIPART_MIXED_CONTENT_BOUNDARY));
        }
        // For EST we don't care about cache-control headers, nothing specified in RFC7030
        //final String cacheControl = con.getHeaderField("Cache-Control");
        //assertNotNull("'Cache-Control' header is not present.", cacheControl);
        //assertEquals("no-cache", cacheControl);
        // If we came here we should have a real response, so read response bytes
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and EST requests are small enough
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
    }

    private static String getProperty(String key, String defaultValue) {
        //If being run from command line
        String result = System.getProperty(key);
        log.debug("System.getProperty("+key+"): " + result);
        if (result == null) {
            //If being run from Eclipse
            final String testProperties = System.getProperty("sun.java.command");
            int cutFrom = testProperties.indexOf(key + "=");
            if (cutFrom >= 0) {
                int to = testProperties.indexOf(" ", cutFrom + key.length() + 1);
                result = testProperties.substring(cutFrom + key.length() + 1, (to >= 0 ? to : testProperties.length())).trim();
            }
        }
        return StringUtils.defaultIfEmpty(result, defaultValue);
    }

    protected PKCS10CertificationRequest generateCertReq(String dn, String challengePassword, String changeToSubjectDN, String changeToSubjectAltName, 
            Extensions exts, final KeyPair keys) throws OperatorCreationException {
        // Generate keys

        // Create challenge password attribute for PKCS10
        // Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
        //
        // Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
        //    type    ATTRIBUTE.&id({IOSet}),
        //    values  SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{\@type})
        // }
        final ASN1EncodableVector attributesVec = new ASN1EncodableVector();
        if (challengePassword != null) {
            final ASN1EncodableVector challpwdattr = new ASN1EncodableVector(); // Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
            // Challenge password attribute, RFC2985
            //challengePassword ATTRIBUTE ::= {
            //        WITH SYNTAX DirectoryString {pkcs-9-ub-challengePassword}
            //        EQUALITY MATCHING RULE caseExactMatch
            //        SINGLE VALUE TRUE
            //        ID pkcs-9-at-challengePassword
            //}
            challpwdattr.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); // Type
            final ASN1EncodableVector pwdvalues = new ASN1EncodableVector();
            pwdvalues.add(new DERUTF8String(challengePassword)); // DirectoryString CHOICE of UTF8String
            final DERSet values = new DERSet(pwdvalues); // values
            challpwdattr.add(values);       
            attributesVec.add(new DERSequence(challpwdattr));
        }
        // ChangeSubjectName, RFC7030 section 4.2.1, RFC6402, section 2.8
        final ASN1EncodableVector changesubjectnameattr = new ASN1EncodableVector(); // Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
        final ASN1EncodableVector changeSubjectName = new ASN1EncodableVector();
        // ChangeSubjectName attribute
        // The actual ChangeSubjectName value
        // ChangeSubjectName ::= SEQUENCE {
        //    subject             Name OPTIONAL,
        //    subjectAlt          SubjectAltName OPTIONAL
        //}
        //(WITH COMPONENTS {..., subject PRESENT} |
        //      COMPONENTS {..., subjectAlt PRESENT} )
        boolean useChangeSubjectNameAttribute = false;
        if (changeToSubjectDN != null) {
            changesubjectnameattr.add(EstConfiguration.id_cmc_changeSubjectName); // Type
            final X500Name changenameValue = new X500Name(CeSecoreNameStyle.INSTANCE, changeToSubjectDN);
            changeSubjectName.add(changenameValue);
            useChangeSubjectNameAttribute = true;
        }
        if (changeToSubjectAltName != null) {
            if (!useChangeSubjectNameAttribute) {
                changesubjectnameattr.add(EstConfiguration.id_cmc_changeSubjectName);
            }
            final GeneralNames altName = CertTools.getGeneralNamesFromAltName(changeToSubjectAltName);
            changeSubjectName.add(altName);
            useChangeSubjectNameAttribute = true;
        }
        if (useChangeSubjectNameAttribute) {
            final ASN1EncodableVector changevalues = new ASN1EncodableVector();    
            changevalues.add(new DERSequence(changeSubjectName));
            final DERSet values = new DERSet(changevalues); // values
            changesubjectnameattr.add(values);
            attributesVec.add(new DERSequence(changesubjectnameattr));
        }
        if (exts != null) {
            ASN1EncodableVector extensionattr = new ASN1EncodableVector();
            extensionattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            extensionattr.add(new DERSet(exts));
            attributesVec.add(new DERSequence(extensionattr));
        }
        // Complete the Attribute section of the request, the set (Attributes) contains two sequences (Attribute)
        DERSet attributes = new DERSet(attributesVec);
        // Create PKCS#10 certificate request
        final PKCS10CertificationRequest p10request = CertTools.genPKCS10CertificationRequest("SHA256WithECDSA",
                CertTools.stringToBcX500Name(dn), keys.getPublic(), attributes, keys.getPrivate(), null);
        return p10request;
    }

    /**
     * 
     * @param serverCertCaInfo CA that issued the client certificate, a CA trusted for TLS connections (configurable with target.servercert.ca)
     * @param clientKeys client keys to be imported into client keystore
     * @param clientCert client certificate to be imported into client keystore, need to be issued by serverCertCa in order for clint TLS to work
     * @throws CertificateEncodingException 
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    protected void setupClientKeyStore(final CAInfo serverCertCaInfo, final KeyPair clientKeys, final X509Certificate clientCert) 
            throws CertificateEncodingException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        final List<Certificate> trustedCaCertificateChain = serverCertCaInfo.getCertificateChain();
        // Login Certificate setup:
        // - - Import trusted CA (configurable with target.clientcert.ca) into loginKeyStore
        // - Sign a certificate using this CA
        // - RestApiTestUser certificate and private key import into loginKeyStore
        // admin
        CLIENT_KEYSTORE = initJksKeyStore(LOGIN_STORE_PATH);
        /*
        Only when we need to add the user to a role, which we don't for EST re-enroll
        
        final Role role = roleSession.getRole(ADMIN, null, SUPER_ADMINISTRATOR_ROLE_NAME);
        ROLE_MEMBER = roleMemberSession.persist(ADMIN,
                new RoleMember(
                        X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                        clientCertCaInfo.getCAId(),
                        X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                        AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                        CERTIFICATE_USER_NAME,
                        role.getRoleId(),
                        CERTIFICATE_USER_NAME + " for REST API Tests"
                )
        );
        */
        importDataIntoJksKeystore(LOGIN_STORE_PATH, CLIENT_KEYSTORE, CertTools.getPartFromDN(CertTools.getSubjectDN(clientCert), "CN"), 
                trustedCaCertificateChain.get(0).getEncoded(), clientKeys, clientCert.getEncoded());

    }
    private static KeyStore initJksKeyStore(final String keyStoreFilePath) 
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        final File file = new File(keyStoreFilePath);
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        if (file.exists()) {
            keyStore.load(new FileInputStream(file), KEY_STORE_PASSWORD.toCharArray());
        } else {
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(file), KEY_STORE_PASSWORD.toCharArray());
        }
        file.deleteOnExit(); // When this process stops (test completed) remove the temporary file 
        return keyStore;
    }
    
    /** Adds the common name to the Super Administrator Role
     * 
     * @param clientCertCaID the CA that issued the certificate to add to role
     * @param certCN the common name of the certificate to add to role
     * @throws AuthorizationDeniedException if unauthorized to modify role
     */
    protected RoleMember addToSuperAdminRole(final int clientCertCaID, final String certCN) throws AuthorizationDeniedException {
        final Role role = roleSession.getRole(ADMIN, null, SUPER_ADMINISTRATOR_ROLE_NAME);
        RoleMember member = roleMemberSession.persist(ADMIN,
                new RoleMember(
                        X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                        clientCertCaID, RoleMember.NO_PROVIDER,
                        X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                        AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                        certCN,
                        role.getRoleId(),
                        certCN + " for EST System Tests"
                )
        );
        return member;
    }

    /** Removed the common name from the Super Administrator Role
     * 
     * @param roleMemberId the ID of the RoleMember that should be removed
     * @throws AuthorizationDeniedException if unauthorized to modify role
     */
    protected void removeFromSuperAdminRole(final int roleMemberId) throws AuthorizationDeniedException {
        roleMemberSession.remove(ADMIN, roleMemberId);
    }

    /** 
     * Assumes that keyStore already exists in keyStoreFilePath and simply adds content to this already existing keystore
     */
    private static void importDataIntoJksKeystore(
            final String keyStoreFilePath,
            final KeyStore keyStore,
            final String keyStoreAlias,
            final byte[] issuerCertificateBytes,
            final KeyPair keyPair,
            final byte[] certificateBytes
    ) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        // Remove any old entries
        @SuppressWarnings("rawtypes")
        final Enumeration aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            keyStore.deleteEntry((String)aliases.nextElement());            
        }
        // Add the certificate
        keyStore.setCertificateEntry(keyStoreAlias, CertTools.getCertfromByteArray(issuerCertificateBytes, Certificate.class));
        // Add the key if exists
        if(keyPair != null) {
            final Certificate[] chain = { CertTools.getCertfromByteArray(certificateBytes, Certificate.class) };
            keyStore.setKeyEntry(keyStoreAlias, keyPair.getPrivate(), KEY_STORE_PASSWORD.toCharArray(), chain);
        }
        // Save the new keystore contents
        final FileOutputStream fileOutputStream = new FileOutputStream(keyStoreFilePath);
        keyStore.store(fileOutputStream, KEY_STORE_PASSWORD.toCharArray());
        fileOutputStream.close();
    }
    
    protected static X509Certificate getCertFromResponse(byte[] resp) throws Exception {
        final CMSSignedData respmsg = new CMSSignedData(Base64.decode(resp));
        final Store<X509CertificateHolder> certstore = respmsg.getCertificates();
        final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
        assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());
        final X509CertificateHolder certHolder = certs.iterator().next();
        return CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
    }
    
    protected static X509Certificate getCertFromKeygenResponse(byte[] resp) throws Exception {
        String response = new String(resp);
        int startBoundary = response.indexOf(MULTIPART_MIXED_CONTENT_BOUNDARY);
        int middleBoundary = response.indexOf(MULTIPART_MIXED_CONTENT_BOUNDARY, startBoundary + MULTIPART_MIXED_CONTENT_BOUNDARY.length() + 2);
        int endBoundary = response.indexOf(MULTIPART_MIXED_CONTENT_BOUNDARY, middleBoundary + MULTIPART_MIXED_CONTENT_BOUNDARY.length() + 2);
        // extra CRLF + double hyphens on both ends
        String encodedCertPart = response.substring(middleBoundary + MULTIPART_MIXED_CONTENT_BOUNDARY.length() + 4, endBoundary - 4).strip();
        int firstHeaderEnd = encodedCertPart.indexOf("\n");
        int secondHeaderEnd = encodedCertPart.indexOf("\n", firstHeaderEnd+4);
        String encodedCert = encodedCertPart.substring(secondHeaderEnd+2).strip();
        return getCertFromResponse(encodedCert.getBytes());
    }

}
