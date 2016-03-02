/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package se.primekey.ejbca.autoenroll;

import java.io.IOException;
import java.net.URL;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;

/**
 * @author Daniel Horn, SiO2 Corp.
 * 
 * @version $Id$
*/

// TODO All or most of these calls are made from the main thread.
// How do we make these calls asynchronously so that the results can be used in
// the UI? (eg, SwingUtilities.InvokeLater)
public class WebServiceConnection {

    private static final Logger log = Logger.getLogger(WebServiceConnection.class);

    private boolean bConnected = false;

    private EjbcaWSService service = null;
    private EjbcaWS ejbcaraws = null;

    private ApplicationProperties props = null;
    private boolean bUseSystemProperties = true;

    private String strEjbcaVersion = "";

    /**
     * 
     */
    public WebServiceConnection() {
    }

    // Used for testing proposed settings without using System.setProperty calls
    public WebServiceConnection(ApplicationProperties props) {
        this.props = props;
        bUseSystemProperties = false;
    }

    private ApplicationProperties getProps() {
        if (null == props) {
            assert (false);
        }
        return props;
    }

    java.security.KeyStore loadKeyStore() throws Exception {
        ApplicationProperties properties = getProps();

        String strKeyStore = properties.getKeyStoreStr();
        assert (strKeyStore.endsWith(".jks"));

        // TODO Change to match extension of actual keystore file or assume that
        // it is always default type (jks)?
        // For now, we assume that latter.
        java.security.KeyStore ks = null;
        java.io.FileInputStream fis = null;
        try {
            ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
            // get user password and file input stream
            char[] password = properties.getKeyStorePassword().toCharArray();

            fis = new java.io.FileInputStream(strKeyStore);
            ks.load(fis, password);
        } catch (Exception e1) {
            //			e1.printStackTrace();

            throw e1;
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return ks;
    }

    java.security.KeyStore loadTrustKeyStore() throws Exception {
        ApplicationProperties properties = getProps();

        String strKeyStore = properties.getTrustedKeyStoreStr();
        assert (strKeyStore.endsWith(".jks"));

        // TODO Change to match extension of actual keystore file or assume that
        // it is always default type (jks)?
        // For now, we assume that latter.
        java.security.KeyStore ks = null;
        java.io.FileInputStream fis = null;
        try {
            ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
            // get user password and file input stream
            char[] password = properties.getTrustedKeyStorePassword().toCharArray();

            fis = new java.io.FileInputStream(strKeyStore);
            ks.load(fis, password);
        } catch (Exception e1) {
            //			e1.printStackTrace();

            throw e1;
        }

        finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return ks;
    }

    java.security.KeyStore loadTrustKeyStore(String strKeyStore, String strPassword) throws Exception {
        assert (strKeyStore.endsWith(".jks"));

        // TODO Change to match extension of actual keystore file or assume that
        // it is always default type (jks)?
        // For now, we assume that latter.
        java.security.KeyStore ks = null;
        java.io.FileInputStream fis = null;
        try {
            ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
            // get user password and file input stream
            char[] password = strPassword.toCharArray();

            fis = new java.io.FileInputStream(strKeyStore);
            ks.load(fis, password);
        } catch (Exception e1) {
            //			e1.printStackTrace();

            throw e1;
        }

        finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return ks;
    }

    private void init() throws Exception {
        if (bConnected) {
            return;
        }

        ApplicationProperties properties = getProps();

        try {
            // Create a new SSLContext each time app server authentication settings may have changed (or when we want to test the settings).
            if (!bUseSystemProperties) {
                setNewDefaultSSLSocketFactory();
            }

            CryptoProviderTools.installBCProvider();

            final QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");

            // Set urlstr to appserver
            // eg, "https://ejbca.course:8443/ejbca/ejbcaws/ejbcaws?wsdl"
            String urlstr = properties.getUrlWebService();

            if (bUseSystemProperties) {
                String strTrustedKeyStore = properties.getTrustedKeyStoreStr();

                System.setProperty("javax.net.ssl.trustStore", strTrustedKeyStore);
                System.setProperty("javax.net.ssl.trustStorePassword", properties.getTrustedKeyStorePassword());

                // Note that we do not assume that the trustStore and the
                // keyStore
                // are
                // one and the same (though, in practice, they may well be).
                System.setProperty("javax.net.ssl.keyStore", properties.getKeyStoreStr());
                System.setProperty("javax.net.ssl.keyStorePassword", properties.getKeyStorePassword());
            }

            service = new EjbcaWSService(new URL(urlstr), qname);
            ejbcaraws = service.getEjbcaWSPort();

            bConnected = true;
        }
        // How we want to handle errors is left to the consumer of this class.
        // For example, we may want to provide a one line message by default to
        // the user with an option for displaying a stack trace in a text pane
        // from it can be copied and emailed to tech support.  (See how SiO2MessagePanel is used).
        catch (Exception exc) {
            //			exc.printStackTrace();

            disconnect();

            // Rethrow exception so that consumer of this method can display
            // message and stack trace if necessary.
            throw exc;
        }
    }

    // This should be called whenever the settings for connecting to an appserver change.
    // Otherwise, Java's SSL session caching may result in an unexpected behavior.
    // In particular, if the keystore or trust keystore settings are incorrect (incorrect filename, password, or privileges),
    // then authentication with the server will still fail even after the values are corrected.
    // Vice versa, if the settings are correct and an authenticated session is successfully created, then
    // a session with the same server may still succeed even if the settings are changed to incorrect values.
    // If this routine is not called, one may have to exit and re-start the application to remedy the problem.
    void setNewDefaultSSLSocketFactory() throws Exception {
        ApplicationProperties properties = getProps();

        SSLContext sslContext = null;
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(loadKeyStore(), properties.getKeyStorePassword().toCharArray());
            KeyManager km[] = kmf.getKeyManagers();

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            java.security.KeyStore trustks = loadTrustKeyStore();
            tmf.init(trustks);
            TrustManager tm[] = tmf.getTrustManagers();

            sslContext = SSLContext.getInstance("TLS");
            // TODO null or "new SecureRandom()" for third argument?
            // null means the default implementation will be used.
            sslContext.init(km, tm, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        } catch (Exception e1) {
            //			e1.printStackTrace();

            throw e1;
        }
    }

    private void disconnect() {
        bConnected = false;

        ejbcaraws = null;
        service = null;
    }

    /*
     * Test for the existence of web server. The following call does not require
     * any authentication.
     */
    boolean test() {
        ApplicationProperties properties = getProps();

        // The following method indicated in the documentation
        CryptoProviderTools.installBCProviderIfNotAvailable();
        // is deprecated and should be replaced by:
        //		CryptoProviderTools.installBCProvider();

        final QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
        try {
            // TODO: *** Make user configurable setting if below ports may change from defaults?
            // Will ports always be 8443 and 8080?
            // Set urlstr to appserver
            // String urlstr =
            // "https://ejbca.course:8443/ejbca/ejbcaws/ejbcaws?wsdl";
            String urlstr0 = properties.getUrlWebService();
            assert (urlstr0.startsWith("https:"));
            int index = urlstr0.indexOf(":", 6);
            int indexSlash = urlstr0.indexOf("/", index);
            // TODO Replace this with new url string built using URL class.
            String urlstr = "http:" + urlstr0.substring(6, index + 1) + "8080"
            //			String urlstr = "http:" + urlstr0.substring(6, index + 1) + "8442"
                    + urlstr0.substring(indexSlash);

            String strTrustedKeyStore = properties.getTrustedKeyStoreStr();

            System.setProperty("javax.net.ssl.trustStore", strTrustedKeyStore);
            System.setProperty("javax.net.ssl.trustStorePassword", properties.getTrustedKeyStorePassword());

            System.setProperty("javax.net.ssl.keyStore", properties.getKeyStoreStr());
            System.setProperty("javax.net.ssl.keyStorePassword", properties.getKeyStorePassword());

            // TODO For non-authenticated call below, these properties are not
            // used at all.
            // Should we temporarily clear them as in:
            /*
             * System.setProperty("javax.net.ssl.trustStore", "");
             * System.setProperty("javax.net.ssl.trustStorePassword", "");
             * System.setProperty("javax.net.ssl.keyStore", "");
             * System.setProperty("javax.net.ssl.keyStorePassword", "");
             */

            // TODO *** Why is https needed here?
            EjbcaWSService service = new EjbcaWSService(new URL(urlstr0), qname);
            //			EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
            EjbcaWS ejbcaraws = service.getEjbcaWSPort();

            strEjbcaVersion = ejbcaraws.getEjbcaVersion();

            if (log.isDebugEnabled()) {
                System.out.println("Ejbca Version: [" + getEjbcaVersion() + "]");
            }

            // *** DPH: Test
            if (true) {
                String str2 = ejbcaraws.getEjbcaVersion();
                System.out.println("EjbcaVersion2: {" + str2 + "}");

                // Do we have access to field names in EndEntityProfile.java?
                System.out.println("UserName field name = [" + org.ejbca.core.model.ra.raadmin.EndEntityProfile.USERNAME + "]");
            }

            return true;
        } catch (Exception exc) {
            exc.printStackTrace();
            System.err.println("*** Could not connect to non-authenticated web service call getEjbcaVersion()");

            return false;
        }
    }

    List<NameAndId> getEndEntityProfiles() throws Exception {
        init();

        try {
            return ejbcaraws.getAuthorizedEndEntityProfiles();
        } catch (AuthorizationDeniedException_Exception e) {
            disconnect();

            e.printStackTrace();

            throw e;
        } catch (EjbcaException_Exception e) {
            disconnect();

            e.printStackTrace();

            throw e;
        }
    }

    List<NameAndId> getAvailableCertificateProfiles(int idEndEntityProfile) throws Exception {
        init();

        try {
            return ejbcaraws.getAvailableCertificateProfiles(idEndEntityProfile);
        } catch (AuthorizationDeniedException_Exception e) {
            disconnect();

            e.printStackTrace();

            throw e;
        } catch (EjbcaException_Exception e) {
            disconnect();

            e.printStackTrace();

            throw e;
        }
    }

    List<NameAndId> getAvailableCAs() throws Exception {
        init();

        try {
            return ejbcaraws.getAvailableCAs();
        } catch (AuthorizationDeniedException_Exception e) {
            disconnect();

            //			e.printStackTrace();

            throw e;
        } catch (EjbcaException_Exception e) {
            disconnect();

            //			e.printStackTrace();

            throw e;
        }
    }

    List<NameAndId> getAvailableCAsInProfile(int idEndEntityProfile) throws Exception {
        init();

        try {
            return ejbcaraws.getAvailableCAsInProfile(idEndEntityProfile);
        } catch (AuthorizationDeniedException_Exception e) {
            disconnect();

            e.printStackTrace();

            throw e;
        } catch (EjbcaException_Exception e) {
            disconnect();

            e.printStackTrace();

            throw e;
        }
    }

    // Use explicit package name for KeyStore instead of import here because we
    // also use java.security.KeyStore elsewhere in this file.
    org.ejbca.core.protocol.ws.client.gen.KeyStore softTokenRequest(UserDataVOWS userData, java.lang.String hardTokenSN, java.lang.String keyspec,
            java.lang.String keyalg) throws Exception {
        init();

        try {
            return ejbcaraws.softTokenRequest(userData, hardTokenSN, keyspec, keyalg);
        } catch (EjbcaException_Exception e) {
            disconnect();

            e.printStackTrace();

            throw e;
        }
        // TODO Do we want the long list of individual exceptions or the single
        // catch all below?
        catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    CertificateResponse certificateRequest(UserDataVOWS userData, java.lang.String requestData, int requestType, java.lang.String hardTokenSN,
            java.lang.String responseType) throws Exception {
        init();

        try {
            return ejbcaraws.certificateRequest(userData, requestData, requestType, hardTokenSN, responseType);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    void editUser(UserDataVOWS userdata) throws Exception {
        init();

        try {
            ejbcaraws.editUser(userdata);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    // Use explicit package name for KeyStore instead of import here because we
    // also use java.security.KeyStore elsewhere in this file.
    org.ejbca.core.protocol.ws.client.gen.KeyStore pkcs12Req(java.lang.String username, java.lang.String password, java.lang.String hardTokenSN,
            java.lang.String keyspec, java.lang.String keyalg) throws Exception {
        init();

        try {
            return ejbcaraws.pkcs12Req(username, password, hardTokenSN, keyspec, keyalg);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    CertificateResponse pkcs10Request(java.lang.String username, java.lang.String password, java.lang.String pkcs10, java.lang.String hardTokenSN,
            java.lang.String responseType) throws Exception {
        init();

        try {
            return ejbcaraws.pkcs10Request(username, password, pkcs10, hardTokenSN, responseType);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    java.util.List<org.ejbca.core.protocol.ws.client.gen.Certificate> getLastCertChain(java.lang.String username) throws Exception {
        init();

        try {
            return ejbcaraws.getLastCertChain(username);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    java.util.List<UserDataVOWS> findUser(UserMatch usermatch) throws Exception {
        init();

        try {
            return ejbcaraws.findUser(usermatch);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    java.util.List<Certificate> findCerts(java.lang.String username, boolean onlyValid) throws Exception {
        init();

        try {
            return ejbcaraws.findCerts(username, onlyValid);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    RevokeStatus checkRevokationStatus(java.lang.String issuerDN, java.lang.String certificateSN) throws Exception {
        init();

        try {
            return ejbcaraws.checkRevokationStatus(issuerDN, certificateSN);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    void revokeUser(java.lang.String username, int reason, boolean deleteUser) throws Exception {
        init();

        try {
            ejbcaraws.revokeUser(username, reason, deleteUser);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    void revokeCert(java.lang.String issuerDN, java.lang.String certificateSN, int reason) throws Exception {
        init();

        try {
            ejbcaraws.revokeCert(issuerDN, certificateSN, reason);
        } catch (Exception e) {
            e.printStackTrace();

            throw e;
        }
    }

    String getEjbcaVersion() {
        return strEjbcaVersion;
    }

}
