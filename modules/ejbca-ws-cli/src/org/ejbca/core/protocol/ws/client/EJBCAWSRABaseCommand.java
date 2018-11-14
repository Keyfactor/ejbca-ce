package org.ejbca.core.protocol.ws.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URL;
import java.security.AuthProvider;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Properties;

import javax.net.ssl.KeyManagerFactory;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

import org.cesecore.keys.token.p11.P11Slot;
import org.cesecore.keys.token.p11.P11SlotUser;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.provider.TLSProvider;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;

/**
 * Base class inherited by all EJBCA RA WS cli commands.
 * Checks the property file and creates a webservice connection.
 *  
 * $Id$
 */

public abstract class EJBCAWSRABaseCommand implements P11SlotUser {
    
    final protected String[] args;
    private org.ejbca.core.protocol.ws.client.gen.EjbcaWS ejbcaraws = null;
    final private URL webServiceURL;
    final private Exception exception;
    
    
    protected static final String[] REASON_TEXTS ={"NOT REVOKED",
    	"REV_UNSPECIFIED",			"REV_KEYCOMPROMISE",	"REV_CACOMPROMISE",
        "REV_AFFILIATIONCHANGED",	"REV_SUPERSEDED",		"REV_CESSATIONOFOPERATION",
        "REV_CERTIFICATEHOLD",		"REV_REMOVEFROMCRL",	"REV_PRIVILEGEWITHDRAWN",
        "REV_AACOMPROMISE"};
    
    public static final int NOT_REVOKED = RevokeStatus.NOT_REVOKED;
    public static final int REVOKATION_REASON_UNSPECIFIED = RevokeStatus.REVOKATION_REASON_UNSPECIFIED;
    public static final int REVOKATION_REASON_KEYCOMPROMISE = RevokeStatus.REVOKATION_REASON_KEYCOMPROMISE;
    public static final int REVOKATION_REASON_CACOMPROMISE = RevokeStatus.REVOKATION_REASON_CACOMPROMISE;
    public static final int REVOKATION_REASON_AFFILIATIONCHANGED = RevokeStatus.REVOKATION_REASON_AFFILIATIONCHANGED;
    public static final int REVOKATION_REASON_SUPERSEDED = RevokeStatus.REVOKATION_REASON_SUPERSEDED;
    public static final int REVOKATION_REASON_CESSATIONOFOPERATION = RevokeStatus.REVOKATION_REASON_CESSATIONOFOPERATION;
    public static final int REVOKATION_REASON_CERTIFICATEHOLD = RevokeStatus.REVOKATION_REASON_CERTIFICATEHOLD;
    public static final int REVOKATION_REASON_REMOVEFROMCRL = RevokeStatus.REVOKATION_REASON_REMOVEFROMCRL;
    public static final int REVOKATION_REASON_PRIVILEGESWITHDRAWN = RevokeStatus.REVOKATION_REASON_PRIVILEGESWITHDRAWN;
    public static final int REVOKATION_REASON_AACOMPROMISE = RevokeStatus.REVOKATION_REASON_AACOMPROMISE;
    
    protected static final int[] REASON_VALUES = {NOT_REVOKED,REVOKATION_REASON_UNSPECIFIED, 
         REVOKATION_REASON_KEYCOMPROMISE, REVOKATION_REASON_CACOMPROMISE,
         REVOKATION_REASON_AFFILIATIONCHANGED, REVOKATION_REASON_SUPERSEDED,
         REVOKATION_REASON_CESSATIONOFOPERATION, REVOKATION_REASON_CERTIFICATEHOLD,
         REVOKATION_REASON_REMOVEFROMCRL, REVOKATION_REASON_PRIVILEGESWITHDRAWN,
         REVOKATION_REASON_AACOMPROMISE};
    
    EJBCAWSRABaseCommand(String[] args) {
        this.args = args;
        final Properties props = new Properties();
        URL tmpURL = null;
        Exception tmpException = null;
        try {
            try {
                props.load(new FileInputStream("ejbcawsracli.properties"));
            } catch (FileNotFoundException e) {
                // Try in parent directory
                props.load(new FileInputStream("../ejbcawsracli.properties"));
            }
            CryptoProviderTools.installBCProvider();
            final String sharedLibraryPath = props.getProperty("ejbcawsracli.p11.sharedlibrary");
            final String trustStorePath = props.getProperty("ejbcawsracli.truststore.path");
            if ( trustStorePath!=null  ) {
                checkIfFileExists(trustStorePath);
                System.setProperty("javax.net.ssl.trustStore", trustStorePath);
            }
            final String password; {
                final String tmpPassword = props.getProperty("ejbcawsracli.keystore.password");
                if ( tmpPassword==null ) {            	
                    System.out.print("Enter keystore password: ");
                    password = new String(System.console().readPassword());
                }else{
                    password = tmpPassword;
                }
            }
            if ( sharedLibraryPath!=null ) {
                checkIfFileExists(sharedLibraryPath);
                final String sSlot =  props.getProperty("ejbcawsracli.p11.slot");
                final Pkcs11SlotLabelType type = Pkcs11SlotLabelType.getFromKey(props.getProperty("ejbcawsracli.p11.slotlabeltype"));
                final P11Slot slot = P11Slot.getInstance(sSlot, sharedLibraryPath, type, null, this, 0, true);// no CA set ID to 0 to indicate just one user
                final AuthProvider provider = (AuthProvider) slot.getProvider();
                final String providerName = provider.getName();
                final PasswordHandler handler = new PasswordHandler(password);
                provider.login(null, handler);
                handler.clean();
                System.setProperty("javax.net.ssl.keyStoreType", "pkcs11");
                System.setProperty("javax.net.ssl.keyStoreProvider", providerName);
                System.setProperty("javax.net.ssl.keyStore", "NONE");
                if ( trustStorePath==null ) {
                    final Provider tlsProvider = new TLSProvider();
                    Security.addProvider(tlsProvider);
                    Security.setProperty("ssl.TrustManagerFactory.algorithm", "AcceptAll");
                }
            } else {
                final String keyStorePath = props.getProperty("ejbcawsracli.keystore.path", "keystore.jks");
                checkIfFileExists(keyStorePath);
                System.setProperty("javax.net.ssl.keyStore", keyStorePath);
                if (keyStorePath.endsWith(".p12")) {
                	System.setProperty("javax.net.ssl.keyStoreType", "pkcs12");
                }
                if ( trustStorePath==null  ) {
                    if (keyStorePath.endsWith(".p12")) {
                        final Provider tlsProvider = new TLSProvider();
                        Security.addProvider(tlsProvider);
                        Security.setProperty("ssl.TrustManagerFactory.algorithm", "AcceptAll");
                    } else {
                        System.setProperty("javax.net.ssl.trustStore", keyStorePath);
                    }
                }
                System.setProperty("javax.net.ssl.keyStorePassword", password);
            }
            tmpURL = new URL(props.getProperty("ejbcawsracli.url", "https://localhost:8443/ejbca/ejbcaws/ejbcaws") + "?wsdl");
            try {
                KeyManagerFactory.getInstance("NewSunX509");
                //getPrintStream().println("Using NewSunX509 KeyManagerFactory.");
                Security.setProperty("ssl.KeyManagerFactory.algorithm", "NewSunX509");
            } catch (NoSuchAlgorithmException e) {
                // Using IBM Java
                getPrintStream().println("Using default KeyManagerFactory, NewSunX509 is not available.");                
            }
        } catch( Exception e ) {
            tmpException = e;
        }
        this.exception = tmpException;
        this.webServiceURL = tmpURL;
    }
    private class PasswordHandler implements CallbackHandler {
        private char password[];
        PasswordHandler(String _password) {
            this.password = _password.toCharArray();
        }
        /* (non-Javadoc)
         * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
         */
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for ( int i=0; i<callbacks.length; i++) {
                try {
                    ((PasswordCallback)callbacks[i]).setPassword(this.password);
                } catch( Throwable t ) {
                    System.out.println("callback class: "+callbacks[i].getClass().getCanonicalName());
                }
            }
        }
        void clean() {
            this.password = null;
        }
    }
    private void checkIfFileExists(String fileName) throws Exception {
        if ( fileName.equals("NONE") ) {
            return;
        }
        final File f = new File(fileName);
        if (!f.exists()) {
            throw new Exception("File '"+fileName+"' does not exist");
        }
    }
    /**
     * Method creating a connection to the webservice
     * using the information stored in the property files.
     * If a connection already is established this connection will be used
     * @throws Exception 
     */
    protected EjbcaWS getEjbcaRAWS() throws Exception{
        return getEjbcaRAWS(false);
    }
    /**
     * Method creating a connection to the webservice
     * using the information stored in the property files.
     * A new connection will be created for each call.
     * @throws Exception 
     */
    protected EjbcaWS getEjbcaRAWSFNewReference() throws  Exception {
        return getEjbcaRAWS(true);
    }
    private EjbcaWS getEjbcaRAWS(boolean bForceNewReference) throws Exception {       
        if ( this.exception!=null ) {
            throw this.exception;
        }
        if(this.ejbcaraws==null || bForceNewReference){
            final QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
            final EjbcaWSService service = new EjbcaWSService(this.webServiceURL,qname);
            if ( bForceNewReference ) {
                return service.getEjbcaWSPort();
            }
            this.ejbcaraws = service.getEjbcaWSPort();
        }
        return this.ejbcaraws;
    }

    protected PrintStream getPrintStream(){
        return System.out;
    }
    
    protected int getRevokeReason(String reason) throws Exception{
        for(int i=0;i<REASON_TEXTS.length;i++){
           if(REASON_TEXTS[i].equalsIgnoreCase(reason)){
               return REASON_VALUES[i];
           }
        }        
        getPrintStream().println("Error : Unsupported reason " + reason);
        usage();
        System.exit(-1); // NOPMD, this is not a JEE app
        return 0;
    }
    
    protected String getRevokeReason(int reason) {
        for(int i=0;i<REASON_VALUES.length;i++){
               if(REASON_VALUES[i]==reason){
                   return REASON_TEXTS[i];
               }
            }        
        getPrintStream().println("Error : Unsupported reason " + reason);
        usage();
        System.exit(-1); // NOPMD, this is not a JEE app
        return null;        
    }
    
    /**
     * Print usage information.
     */
    protected abstract void usage();

    @Override
    public void deactivate() {
    }
    @Override
    public boolean isActive() {
        return true;
    }
}
