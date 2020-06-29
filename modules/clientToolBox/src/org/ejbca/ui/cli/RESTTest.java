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

package org.ejbca.ui.cli;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContexts;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.util.PerformanceTest;
import org.ejbca.util.PerformanceTest.Command;
import org.ejbca.util.PerformanceTest.CommandFactory;
import org.ejbca.util.PerformanceTest.NrOfThreadsAndNrOfTests;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * Used to stress test the REST interface.
 * Example usage, testing 25 threads making REST API calls to ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll:
 * ./ejbcaClientToolBox.sh RESTTest localhost:8443 ~/tmp/ManagementCA.cacert.pem ManagementCA ENDUSER EMPTY ../../p12/superadmin.p12 ejbca 25 1
 *
 * @version $Id$
 */
class RESTTest extends ClientToolBox {
    static private class StressTest {
        final PerformanceTest performanceTest;

        private final KeyPair keyPair;
        private final String hostName;
        private final X509Certificate cacert;
        private final String caName;
        private final String cpName;
        private final String eepName;
        private final KeyStore keystore;
        private final String keystorePwd;        
        final String resultCertFilePrefix;
        final SSLContext sslContext;
        
        @SuppressWarnings("synthetic-access")
        StressTest( final String _hostName,
                    final X509Certificate _cacert,
                    final String _caName,
                    final String _cpName,
                    final String _eepName,    
                    final KeyStore _keystore,
                    final String _keystorePwd,
                    final int numberOfThreads,
                    final int numberOfTests,
                    final int waitTime,
                    final String _resultCertFilePrefix) throws Exception {
            this.hostName = _hostName;
            this.cacert = _cacert;
            this.caName = _caName;
            this.cpName = _cpName;
            this.eepName = _eepName;
            this.keystore = _keystore;
            this.keystorePwd = _keystorePwd;
            this.resultCertFilePrefix = _resultCertFilePrefix;

            final KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(2048);
            this.keyPair = keygen.generateKeyPair();

            // Create the sslContext once (per thread) at startup, because this takes time that we don't 
            // want to spend for each HTTPS call 
            sslContext = SSLContexts.custom()
                    .loadKeyMaterial(keystore, keystorePwd.toCharArray())
                    .loadTrustMaterial(keystore, new TrustAllStrategy())
                    .build();

            this.performanceTest = new PerformanceTest();
            this.performanceTest.execute(new MyCommandFactory(), numberOfThreads, numberOfTests, waitTime, System.out);
        }
        private PKCS10CertificationRequest genCertReq(final X500Name userDN) throws IOException {
            // Add an altName extension with an email address
            GeneralNames san = CertTools.getGeneralNamesFromAltName("rfc822Name=tomas@primekey.se");
            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, san);
            final Extensions extensions = extensionsGenerator.generate();
            // Add the extension(s) to the PKCS#10 request as a pkcs_9_at_extensionRequest
            ASN1EncodableVector extensionattr = new ASN1EncodableVector();
            extensionattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            extensionattr.add(new DERSet(extensions));
            // Complete the Attribute section of the request, the set (Attributes) contains one sequence (Attribute)
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new DERSequence(extensionattr));
            DERSet attributes = new DERSet(v);
            try {
                return CertTools.genPKCS10CertificationRequest("SHA256WithRSA", userDN, keyPair.getPublic(), attributes, keyPair.getPrivate(), null);
            } catch (OperatorCreationException e) {
                StressTest.this.performanceTest.getLog().error("Unable to generate CSR: " + e.getLocalizedMessage());
                e.printStackTrace();
                return null;
            }

        }
        
        @SuppressWarnings("unchecked")
        private String sendREST(final PKCS10CertificationRequest pkcs10, final SessionData sessionData) throws Exception {
            // curl -X POST "https://localhost:8443/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{  \"certificate_request\": \"string\",  \"certificate_profile_name\": \"string\",  \"end_entity_profile_name\": \"string\",  \"certificate_authority_name\": \"string\",  \"username\": \"string\",  \"password\": \"string\",  \"include_chain\": true}"            
            //{
            //    "certificate_request": "string",
            //    "certificate_profile_name": "string",
            //    "end_entity_profile_name": "string",
            //    "certificate_authority_name": "string",
            //    "username": "string",
            //    "password": "string",
            //    "include_chain": true
            //  }

            final String restUrl = new StringBuilder().append("https://").append(hostName).append("/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll").toString();

            final String username = "RESTTESTUSER-" + StressTest.this.performanceTest.nextLong();
            final StringWriter pemout = new StringWriter();
            JcaPEMWriter pm = new JcaPEMWriter(pemout);
            pm.writeObject(pkcs10);
            pm.close();
            final String p10pem = pemout.toString();
            JSONObject param = new JSONObject();
            param.put("certificate_request", p10pem);
            param.put("certificate_profile_name", cpName);
            param.put("end_entity_profile_name", eepName);
            param.put("certificate_authority_name", caName);
            param.put("username", username);
            param.put("password", username);
            param.put("include_chain", "false");
            final StringWriter out = new StringWriter();
            param.writeJSONString(out);
            final String payload = out.toString();            
            // connect to EJBCA and send the CSR and get an issued certificate back
            String s = null;
            try (CloseableHttpResponse response = performRESTAPIRequest(restUrl, payload)) {
                final InputStream content = response.getEntity().getContent();
                if (content != null){
                    s = IOUtils.toString(content, StandardCharsets.UTF_8);
                }
                if (response.getStatusLine().getStatusCode() == 404) {
                    StressTest.this.performanceTest.getLog().error("No REST API found (HTTP 404 returned): " + restUrl + ", content: " + s);
                    return null;
                }
                if (response.getStatusLine().getStatusCode() != 200 && response.getStatusLine().getStatusCode() != 201) {
                    StressTest.this.performanceTest.getLog().error("Call to REST API returns error: " + response.getStatusLine().toString() + ", returning null: " + restUrl + ", content: " + s);
                    return null;
                }
                if (s == null) {
                    StressTest.this.performanceTest.getLog().error("We got HTTP 200 or 201 as response code, but no JSON content returned. Unknown error state from EJBCA. Returning null: " + restUrl + ", content: " + s);
                    return null;
                }
            }
            return s;
        }
        
        private CloseableHttpResponse performRESTAPIRequest(final String restUrl, final String payload) throws IOException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
            final HttpPost request = new HttpPost(restUrl); 
            request.setHeader("Content-Type", "application/json");
            request.setEntity(new StringEntity(payload));
            final HttpClientBuilder builder = HttpClientBuilder.create();
            // sslContext should be pre-created because it takes something like 25ms to create, and it's the same for every call (and thread for that matter)
            final CloseableHttpClient httpClient = builder.setSSLContext(sslContext).build(); 
            final CloseableHttpResponse response = httpClient.execute(request);
            return response;
        }

        private X509Certificate checkCertResponse(final SessionData sessionData, final String retMsg) throws IOException, CertificateException {
            //
            // Parse response message JSON
            //
            final JSONParser jsonParser = new JSONParser();
            JSONObject parse = null;
            try {
                parse = (JSONObject) jsonParser.parse(retMsg);
            } catch (ParseException e1) {
                StressTest.this.performanceTest.getLog().error("Response can not be parsed as JSON. See exception: ", e1);
                return null;
            }
            if (parse == null) {
                StressTest.this.performanceTest.getLog().error("No JSON response for certificate received.");
                return null;
            }
            // {
            //    "certificate": [
            //      "string"
            //    ],
            //    "serial_number": "string",
            //    "response_format": "string",
            //    "certificate_chain": [
            //      [
            //        "string"
            //      ]
            //    ]
            //  }
            final String value = (String) parse.get("certificate");
            X509Certificate cert = null;
            if (value != null) {
                // We have a certificate
                cert = CertTools.getCertfromByteArray(Base64.decode(value.getBytes("UTF-8")), X509Certificate.class);
            } else {
                StressTest.this.performanceTest.getLog().error("No certificate in response.");
                return null;
            }
            if (cert == null) {
                StressTest.this.performanceTest.getLog().error("No certificate received");
                return null;
            }
            {
                final X500Name certDN = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
                if (certDN.hashCode() != sessionData.getUserDN().hashCode()) {
                    StressTest.this.performanceTest.getLog().error(
                            "Subject is '" + certDN +
                                    "' but should be '" + sessionData.getUserDN() + '\'');
                    return null;
                }
            }
            if (cert.getIssuerX500Principal().hashCode() != this.cacert.getSubjectX500Principal().hashCode()) {
                StressTest.this.performanceTest.getLog().error(
                        "Issuer is '" + cert.getIssuerX500Principal() + "' but should be '" + this.cacert.getSubjectX500Principal() + '\'');
                return null;
            }
            try {
                cert.verify(this.cacert.getPublicKey());
            } catch (Exception e) {
                StressTest.this.performanceTest.getLog().error("Certificate not verifying. See exception", e);
                return null;
            }
            return cert;
        }

        private class GetCertificate implements Command {
            final private SessionData sessionData;
            GetCertificate(final SessionData sd) {
                this.sessionData = sd;
            }
            @Override
            public boolean doIt() throws Exception {
                this.sessionData.newSession();
                PKCS10CertificationRequest pkcs10 = genCertReq(this.sessionData.getUserDN());
                if (pkcs10 == null) {
                    StressTest.this.performanceTest.getLog().error("No certificate request.");
                    return false;
                }
                // Send request and receive response
                final String resp = sendREST(pkcs10, this.sessionData);
                if ( StringUtils.isEmpty(resp) ) {
                    StressTest.this.performanceTest.getLog().error("No response message.");
                    return false;
                }
                final X509Certificate cert = checkCertResponse(this.sessionData, resp);
                if ( cert==null ) {
                    return false;
                }
                final BigInteger serialNumber = CertTools.getSerialNumber(cert);
                if ( StressTest.this.resultCertFilePrefix!=null ) {
                    try (FileOutputStream fileOutputStream = new FileOutputStream(StressTest.this.resultCertFilePrefix + serialNumber + ".dat")) {
                        fileOutputStream.write(cert.getEncoded());
                    }
                }
                StressTest.this.performanceTest.getLog().result(serialNumber);

                return true;
            }
            @Override
            public String getJobTimeDescription() {
                return "Get certificate";
            }
        }
        class SessionData {
            private int lastNextInt = 0;
            private X500Name userDN;
            final private static int howOftenToGenerateSameUsername = 3;	// 0 = never, 1 = 100% chance, 2=50% chance etc.. 
            SessionData() {
                super();
            }
            private int getRandomAndRepeated() {
                // Initialize with some new value every time the test is started
                // Return the same value once in a while so we have multiple requests for the same username
                if ( this.lastNextInt==0 || howOftenToGenerateSameUsername==0 || StressTest.this.performanceTest.getRandom().nextInt()%howOftenToGenerateSameUsername!=0 ) {
                    this.lastNextInt = StressTest.this.performanceTest.getRandom().nextInt();
                }
                return this.lastNextInt;
            }
            @SuppressWarnings("unused")
            void newSession() {
                final X500NameBuilder x500nb = new X500NameBuilder();
                if ( true ) { // flip to test the other order
                    x500nb.addRDN( BCStyle.CN, "REST Test User Nr " + getRandomAndRepeated() );
                    x500nb.addRDN(BCStyle.O, "REST Test");
                    x500nb.addRDN(BCStyle.C, "SE");
                } else {
                    x500nb.addRDN(BCStyle.C, "SE");
                    x500nb.addRDN(BCStyle.O, "REST Test");
                    x500nb.addRDN( BCStyle.CN, "REST Test User Nr " + getRandomAndRepeated() );
                }
                this.userDN = x500nb.build();
            }
            X500Name getUserDN() {
                return this.userDN;
            }
        }
        private class MyCommandFactory implements CommandFactory {
            @Override
            public Command[] getCommands() {
                final SessionData sessionData = new SessionData();
                return new Command[]{new GetCertificate(sessionData)};//, new Revoke(sessionData)};
            }
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
	protected void execute(String[] args) {
        if ( args.length < 8 ) {
            System.out.println(args[0]+" <hostname:port> <CA certificate filename> <CA name> <certificate profile name> <end entity profile name> <keystore filename> <keystore password> [<'m:n' m # of threads, n # of tests>] [<wait time (ms) between each thread is started>] [<certificate file prefix. set this if you want all received certificates stored on files>]");
            System.out.println("Tests the 'pkcs10enroll' command of the REST API");
            System.out.println("Requirements for the 'REST profiles':");
            System.out.println("EJBCA CA configuration requires 'Enforce unique public keys' to be unchecked, i.e. to not enforce unique public keys. The same key pair is used for all users in order to gain maximum speed in the test client.");
            System.out.println("Sample command: running 25 concurrent threads:");
            System.out.println("./ejbcaClientToolBox.sh RESTTest localhost:8443 ~/tmp/ManagementCA.cacert.pem ManagementCA ENDUSER EMPTY ../../p12/superadmin.p12 ejbca 25 1");
            return;
        }
        final String hostName = args[1];
        final String certFileName = args[2];
        final List<X509Certificate> cacert;
        try {
            cacert = CertTools.getCertsFromPEM(certFileName, X509Certificate.class);
            if (cacert.size() < 1) {
                System.out.println("No CA certificates can be read from file, does the file contain a certificate in PEM format? : " + certFileName);
                return;
            }
        } catch (CertificateParsingException | FileNotFoundException e1) {
            System.out.println("No CA certificates can be read from file, does the file contain a certificate in PEM format? : " + certFileName);
            e1.printStackTrace();
            return;
        }
        final String caName = args[3];
        final String cpName = args[4];
        final String eepName = args[5];
        final String ksFilename = args[6];
        final String ksPwd = args[7];
        final KeyStore keystore;
        try (InputStream keyStoreStream = new FileInputStream(ksFilename)) {
            keystore = KeyStore.getInstance("PKCS12");
            keystore.load(keyStoreStream, ksPwd.toCharArray());
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e1) {
            System.out.println("Client certificate keystore can not be loaded : " + ksFilename);
            e1.printStackTrace();
            return;            
        }
        
        final NrOfThreadsAndNrOfTests notanot = new NrOfThreadsAndNrOfTests(args.length>8 ? args[8] : null);
        final int waitTime = args.length>9 ? Integer.parseInt(args[9].trim()):0;
        final String resultFilePrefix = args.length>10 ? args[10].trim() : null;

        try {
            new StressTest(hostName, cacert.get(0), caName, cpName, eepName, keystore, ksPwd, notanot.getThreads(), notanot.getTests(), waitTime, resultFilePrefix);
        } catch (SecurityException e) {
            throw e; // System.exit() called. Not thrown in normal operation but thrown by the custom SecurityManager when clientToolBoxTest is executed. Must not be caught.
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
    @Override
    protected String getName() {
        return "RESTTest";
    }

}
