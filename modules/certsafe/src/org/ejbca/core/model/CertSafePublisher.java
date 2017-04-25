/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/ 
package org.ejbca.core.model;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keybind.impl.ClientX509KeyManager;
import org.cesecore.keybind.impl.ClientX509TrustManager;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;
import org.ejbca.core.model.ca.publisher.CustomPublisherUiSupport;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * A publisher that sends certificate issuance and life cycle events (revoke and unrevoke)
 * to a HTTPS server. The HTTPS request content (aka. the certificate and other related 
 * data) is sent inside a JSON object.
 * 
 * @version $Id$
 */
public class CertSafePublisher extends CustomPublisherContainer implements ICustomPublisher, CustomPublisherUiSupport {

    private static final long serialVersionUID = 1L;
    private static Logger log = Logger.getLogger(CertSafePublisher.class);    
    
    private InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    private CertificateStoreSessionLocal certificateStoreSession;
    
    private final int DEFAULT_CONNECTIONTIMEOUT = 10000; // 10 000 milliseconds = 10 seconds
    
    /** The URL to the HTTPS server. Should be in the format https://HOST:PORT/RELATIVEURL */
    public static final String certSafeUrlPropertyName = "certsafe.url";
    /** The name of the Authentication Key Binding that will be used for authentication with the HTTPS server */
    public static final String certSafeAuthKeyBindingPropertyName = "certsafe.authkeybindingname";
    /** Timeout on connection to the HTTPS server  */
    public static final String certSafeConnectionTimeOutPropertyName = "certsafe.connectiontimeout";


    private String urlstr = "";
    private String authKeyBindingName = "";
    private int timeout = DEFAULT_CONNECTIONTIMEOUT;
    private URL url = null;


    private HashMap<String, String> revocationReasons = new HashMap<String, String>();

    
    public CertSafePublisher(){}
    
    /**
     * Load used properties.
     * 
     * @param properties
     *            The properties to load.
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
     */
    @Override
    public void init(Properties properties) {
        if (log.isTraceEnabled()) {
            log.trace(">init");
        }
        
        EjbLocalHelper localHelper = new EjbLocalHelper();
        internalKeyBindingMgmtSession = localHelper.getInternalKeyBindingMgmtSession();
        cryptoTokenManagementSession = localHelper.getCryptoTokenManagementSession();
        certificateStoreSession = localHelper.getCertificateStoreSession();

        // Extract system properties
        urlstr = (properties.getProperty(certSafeUrlPropertyName));
        authKeyBindingName = properties.getProperty(certSafeAuthKeyBindingPropertyName);
        timeout = properties.containsKey(certSafeConnectionTimeOutPropertyName)? 
                        Integer.parseInt(properties.getProperty(certSafeConnectionTimeOutPropertyName)) : 
                        DEFAULT_CONNECTIONTIMEOUT;

        // This map translates the revocation reasons in CertificateConstants.reasontext to more readable 
        // text strings (according to CertSafe REST API specifications)
        revocationReasons.put("REV_UNSPECIFIED", "unspecified");
        revocationReasons.put("REV_KEYCOMPROMISE", "keyComprimise");
        revocationReasons.put("REV_CACOMPROMISE", "caComprimise");
        revocationReasons.put("REV_AFFILIATIONCHANGED", "affiliationChanged");
        revocationReasons.put("REV_SUPERSEDED", "superseded");
        revocationReasons.put("REV_CESSATIONOFOPERATION", "cessationOfOperation");
        revocationReasons.put("REV_CERTIFICATEHOLD", "certificateHold");
        revocationReasons.put("REV_UNUSED", "REV_UNUSED");
        revocationReasons.put("REV_REMOVEFROMCRL", "removeFromCrl");
        revocationReasons.put("REV_PRIVILEGEWITHDRAWN", "privilegeWithdrawn");
        revocationReasons.put("REV_AACOMPROMISE", "aaComprimise");
        
    } // init  
    
    private URL getURL() throws MalformedURLException {
        if((url==null) && (urlstr!=null)) {
            url = new URL(urlstr.trim());
        }
        return url;
    }

    @Override
    public List<CustomPublisherProperty> getCustomUiPropertyList() {
        List<CustomPublisherProperty> ret = new ArrayList<CustomPublisherProperty>();
        // Make selection of the remote CertSafe server configurable 
        ret.add(new CustomPublisherProperty(certSafeUrlPropertyName, CustomPublisherProperty.UI_TEXTINPUT, urlstr));
        
        // Authentication key binding we use to authenticate against the remove remote CertSafe server
        if (internalKeyBindingMgmtSession==null) {
            internalKeyBindingMgmtSession = new EjbLocalHelper().getInternalKeyBindingMgmtSession();
        }
        List<InternalKeyBindingInfo> kinfos = internalKeyBindingMgmtSession.getAllInternalKeyBindingInfos(AuthenticationKeyBinding.IMPLEMENTATION_ALIAS);
        ArrayList<String> options = new ArrayList<String>();
        Iterator<InternalKeyBindingInfo> itr = kinfos.iterator();
        while(itr.hasNext()) {
            InternalKeyBindingInfo kinfo = itr.next();
            options.add(kinfo.getName());
        }
        ret.add(new CustomPublisherProperty(certSafeAuthKeyBindingPropertyName, CustomPublisherProperty.UI_SELECTONE, options, options, authKeyBindingName));

        // HTTPS connection timeout
        ret.add(new CustomPublisherProperty(certSafeConnectionTimeOutPropertyName, CustomPublisherProperty.UI_TEXTINPUT, String.valueOf(timeout)));
        return ret;
    }

    /**
     * Sends the certificate in a JSON object to Cert Safe server through HTTPS.
     * 
     * @param incert
     *            The certificate
     * @param status
     *            The certificate status
     * @param revocationReason
     *            The certificate revocation reason if it was revoked
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCertificate(org.ejbca.core.model.log.Admin,
     *      java.security.cert.Certificate, java.lang.String, java.lang.String,
     *      int, int)
     */
    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, 
            String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, 
            long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCertificate, Storing Certificate for user: " + username);
        }
        
       
        // Construct the SSL context for the HTTPS exchange
        SSLSocketFactory sslSocketFactory;
        try {
            checkProperties();
            sslSocketFactory = getSSLSocketFactory(admin);
        } catch (PublisherConnectionException e1) {
            String msg = e1.getLocalizedMessage();
            log.error(msg, e1);
            throw new PublisherException(msg);
        }
        
        final String jsonObject = getJSONString(incert, status, revocationReason);
                
        // Make the HTTPS connection and send the request
        HttpsURLConnection con = null;
        try {
            
            if (log.isDebugEnabled()) {
                log.debug("CertSafe https URL: " + urlstr);
            }

            con = (HttpsURLConnection) getURL().openConnection();
            con.setSSLSocketFactory(sslSocketFactory);
            
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestMethod("POST");
            con.setDoOutput(true);
            con.setConnectTimeout(timeout);
        
            // POST it
            final OutputStream os = con.getOutputStream();
            os.write(jsonObject.getBytes());
            os.close();
            final int responseCode = con.getResponseCode();
            if(responseCode == 200) {
                if(log.isDebugEnabled()) {
                    log.debug("Publish successful, response code 200.");
                }
            } else if( (responseCode >= 400) && (responseCode < 600) ){
                InputStream ins = con.getErrorStream();
                if (ins == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error stream was null, trying InputStream.");
                    }
                    ins = con.getInputStream();
                }
                final String errMsg = getJSONErrorMessage(con.getErrorStream());
                log.error("CERTSAFE ERROR: Publish failed. HTTPS response code: " + responseCode + ". Error message: " + errMsg);
                throw new PublisherException(errMsg);
            }
        } catch (MalformedURLException e) {
            String msg = e.getLocalizedMessage();
            log.error("CERTSAFE ERROR: "+msg, e);
            throw new PublisherException(msg);
        } catch (IOException e) {
            String msg = e.getLocalizedMessage();
            log.error("CERTSAFE ERROR: "+msg, e);
            throw new PublisherException(msg);
        } finally {
            if(con != null) {
                con.disconnect();
            }
        }
        
        if (log.isTraceEnabled()) {
            log.trace("<storeCertificate()");
        }
        return true;
    }
    
    
    /**
     * Does nothing for CertSafe, only certificates are published.
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCRL(org.ejbca.core.model.log.Admin,
     *      byte[], java.lang.String, int)
     */
    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCRL() - does nothing!");
        }
        return true;
    }

    @Override
    public void testConnection() throws PublisherConnectionException {
        if (log.isTraceEnabled()) {
            log.trace("testConnection, Testing connection");
        }
        checkProperties();
        
        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Test CertSafe Connection"));
        
        SSLSocketFactory sslSocketFactory = getSSLSocketFactory(admin);
        try {
            if (log.isDebugEnabled()) {
                log.debug("CertSafe https URL: " + urlstr);
            }
            HttpsURLConnection con = (HttpsURLConnection) getURL().openConnection();
            con.setSSLSocketFactory(sslSocketFactory);
            
            con.setDoOutput(true);
            con.setRequestMethod("GET");
            con.setConnectTimeout(timeout);
            con.connect();
            if(con.getResponseCode() != 200) {
                throw new PublisherConnectionException("Testing connection failed, response code: "+con.getResponseCode());
            }
        } catch (UnknownHostException e) {
            String msg = "Unknown host: "+e.getLocalizedMessage();
            log.info(msg, e);
            throw new PublisherConnectionException(msg); 
        } catch (MalformedURLException e) {
            String msg = e.getLocalizedMessage();
            log.info(msg, e);
            throw new PublisherConnectionException(msg); 
        } catch (ProtocolException e) {
            String msg = e.getLocalizedMessage();
            log.info(msg, e);
            throw new PublisherConnectionException(msg);
        } catch (IOException e) {
            String msg = e.getLocalizedMessage();
            log.info(msg, e);
            throw new PublisherConnectionException(msg);
        }
    }
    
    
    private void checkProperties() throws PublisherConnectionException {
        if (isEmptyString(urlstr) || isEmptyString(authKeyBindingName)) {
            String msg = "Either the property '" + certSafeUrlPropertyName + "' or the property '" + 
                    certSafeAuthKeyBindingPropertyName + "' is not set.";
            log.info(msg);
            throw new PublisherConnectionException(msg);
        }
        
        URL uurl = null;
        try {
            uurl = getURL();
        } catch (MalformedURLException e) {
            String msg = "Could not create a URL object from the value of " + certSafeUrlPropertyName + " property: " + urlstr;
            log.info(msg + ". " + e.getMessage());
            throw new PublisherConnectionException(msg);
        }
        
        String protocol = uurl.getProtocol();
        if(!protocol.equalsIgnoreCase("https")) {
            String msg = "The URL must be a HTTPS address";
            log.info(msg);
            throw new PublisherConnectionException(msg);
        }
        
        if(isEmptyString(uurl.getHost())) {
            String msg = "The URL is missing the hostname";
            log.info(msg);
            throw new PublisherConnectionException(msg);
        }
    }
    
    private SSLSocketFactory getSSLSocketFactory(AuthenticationToken authenticationToken) throws PublisherConnectionException {
        Integer keyBindingID = internalKeyBindingMgmtSession.getIdFromName(authKeyBindingName);
        if (keyBindingID == null) {
            throw new PublisherConnectionException("The authentication key binding '"+authKeyBindingName+"' does not exist.");
        }
        final AuthenticationKeyBinding authenticationKeyBinding;
        try {
            authenticationKeyBinding = (AuthenticationKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBindingReference(authenticationToken, keyBindingID);
        } catch (AuthorizationDeniedException e) {
            String msg = e.getLocalizedMessage();
            log.error(msg, e);
            throw new PublisherConnectionException(msg);
        }
        
        if (authenticationKeyBinding == null) {
            String msg = "AuthenticationKeyBinding '" + authKeyBindingName + "' was not found";
            log.info(msg);
            throw new PublisherConnectionException(msg);
        }
        if(!authenticationKeyBinding.getStatus().equals(InternalKeyBindingStatus.ACTIVE)) {
            String msg = "AuthenticationKeyBinding '" + authKeyBindingName + "' is not active";
            log.info(msg);
            throw new PublisherConnectionException(msg);
        }
        
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(authenticationKeyBinding.getCryptoTokenId());
        final X509Certificate sslCertificate = (X509Certificate) certificateStoreSession.findCertificateByFingerprint(authenticationKeyBinding.getCertificateId());
        final List<X509Certificate> chain = new ArrayList<X509Certificate>();
        chain.add(sslCertificate);
        chain.addAll(getCaCertificateChain(sslCertificate));
        final String alias = authenticationKeyBinding.getKeyPairAlias();
        try {
            List< Collection<X509Certificate> > trustedCertificates = internalKeyBindingMgmtSession.getListOfTrustedCertificates(authenticationKeyBinding);
            final TrustManager trustManagers[] = new X509TrustManager[] { new ClientX509TrustManager(trustedCertificates) };
            final KeyManager keyManagers[] = new X509KeyManager[] { new ClientX509KeyManager(alias, cryptoToken.getPrivateKey(alias), chain) };
            // Now construct a SSLContext using these (possibly wrapped) KeyManagers, and the TrustManagers.
            // We still use a null SecureRandom, indicating that the defaults should be used.
            final SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers, trustManagers, null);
            // Finally, we get a SocketFactory, and pass it on.
            return context.getSocketFactory();
        } catch (KeyManagementException e) {
            String msg = e.getLocalizedMessage();
            log.error(msg, e);
            throw new PublisherConnectionException(msg);
        } catch (NoSuchAlgorithmException e) {
            String msg = e.getLocalizedMessage();
            log.error(msg, e);
            throw new PublisherConnectionException(msg);
        } catch (CryptoTokenOfflineException e) {
            String msg = "The CryptoToken is offline";
            log.error(msg, e);
            throw new PublisherConnectionException(msg);
        } catch (CADoesntExistsException e) {
            String msg = e.getLocalizedMessage();
            log.error(msg, e);
            throw new PublisherConnectionException(msg);
        }
    }
    
    // TODO: This method also exists in OcspResponseGenSSB.. merge! to method call in certificateStoreSession
    private List<X509Certificate> getCaCertificateChain(final X509Certificate leafCertificate) {
        final List<X509Certificate> caCertificateChain = new ArrayList<X509Certificate>();
        X509Certificate currentLevelCertificate = leafCertificate;
        while (!CertTools.getIssuerDN(currentLevelCertificate).equals(CertTools.getSubjectDN(currentLevelCertificate))) {
            final String issuerDn = CertTools.getIssuerDN(currentLevelCertificate);
            currentLevelCertificate = certificateStoreSession.findLatestX509CertificateBySubject(issuerDn);
            if (currentLevelCertificate == null) {
                log.warn("Unable to build certificate chain for SSL authentication certificate with Subject DN '" +
                        CertTools.getSubjectDN(leafCertificate) + "'. CA with Subject DN '" + issuerDn + "' is missing in the database.");
                return null;
            }
            caCertificateChain.add(currentLevelCertificate);
        }
        return caCertificateChain;
    }
    
    /**
     * Returns the input in a String of JSON format:
     * 
     *          {
     *              "status" : STATUS
     *              "revocationReason" : REVOCATION_REASON_IF_ANY
     *              "pem" : THE_CERTIFICATE
     *          }
     *          
     *          
     * @param incert
     * @param status
     * @param revocationReason
     * @return
     * @throws PublisherException
     */
    private String getJSONString(Certificate incert, int status, int revocationReason) throws PublisherException {
        
        JSONObject json = new JSONObject();
        String stat = "";
        if (status == CertificateConstants.CERT_REVOKED) {
            stat = "revoked";
            json.put("revocationReason", revocationReasons.get(CertificateConstants.reasontexts[revocationReason]) );
        //} else if (status == CertificateConstants.CERT_TEMP_REVOKED) {
        //    stat = "suspended";
        } else if ( (status == CertificateConstants.CERT_UNASSIGNED) ||
                     (status == CertificateConstants.CERT_INACTIVE) ) {
            stat = "hold";
        } else if (status == CertificateConstants.CERT_ARCHIVED) {
            stat = "expired";
        } else {
            stat = "active";
        }
        json.put("status", stat);
        
        //Add the certificate to the JSON object
        ArrayList<Certificate> certs =  new ArrayList<Certificate>();
        certs.add(incert);
        String certStr;
        try {
            certStr = new String(CertTools.getPemFromCertificateChain(certs));
        } catch (CertificateException e) {
            String msg = e.getLocalizedMessage();
            log.error(msg, e);
            throw new PublisherException(msg);
        }
        int index = certStr.indexOf(CertTools.BEGIN_CERTIFICATE);
        certStr = certStr.substring(index);
        json.put("pem", certStr);
        String ret = json.toString();
        if(log.isDebugEnabled()) {
            log.debug("Sending the JSON String: " + ret);
        }
        
        return ret;
    }
    
    /**
     * Obtaining a JSON object from the InputStream and returns the error message inside the JSON object.
     * 
     * The JSON object format is:
     *          {
     *              "error" : ERROR_MESSAGE
     *          }
     *          
     * @param errins
     * @return the error message if found. Empty string otherwise
     * @throws IOException
     */
    private String getJSONErrorMessage(InputStream errins) throws IOException {
        if (errins == null) {
            if (log.isDebugEnabled()) {
                log.debug("No error input stream available, returning empty error string.");
            }
            return "";
        }
        byte[] errB = new byte[1024];
        errins.read(errB);
        errins.close();
        String response = new String(errB);
        if (log.isTraceEnabled()) {
            log.trace("Received error response: " + response);
        }
        response = response.substring(0, response.lastIndexOf("}")+1);
        if (log.isDebugEnabled()) {
            log.debug("Received JSON response: " + response);
        }
        
        JSONParser parser = new JSONParser();
        JSONObject json=null;
        try {
            json = (JSONObject) parser.parse(response);
        } catch (ParseException e) {
            log.error("Error parsing JSON response", e);
            return "";
        }
        return (String) json.get("error");
    }
    
    private boolean isEmptyString(String str) {
        return str==null || str.length()==0;
    }
    
    @Override
    public boolean isReadOnly() {
        return false;
    }
    
}
