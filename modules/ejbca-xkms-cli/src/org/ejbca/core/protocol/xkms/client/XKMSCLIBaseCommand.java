package org.ejbca.core.protocol.xkms.client;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Random;

import javax.xml.bind.JAXBElement;

import org.apache.log4j.Logger;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.util.keystore.P12toPEM;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.StatusType;
import org.w3._2002._03.xkms_.UnverifiedKeyBindingType;
import org.w3._2002._03.xkms_.UseKeyWithType;

/**
 * Base class inherited by all XKMS cli commands.
 * Checks the property file and creates a webservice connection.
 *  
 * @author Philip Vendil
 * $Id$
 */

public abstract class XKMSCLIBaseCommand {
	
	private static Logger log = Logger.getLogger(XKMSCLIBaseCommand.class);
	
	protected String[] args = null;
	private XKMSInvoker xkms = null;
	private Properties props = null;
	private String password = null;
	
	protected X509Certificate clientCert = null;
	protected Key privateKey = null;
	private Collection<Certificate> catrustlist = null;
	
	
	protected static final String[] REASON_TEXTS ={"NOT REVOKED",
		"REV_UNSPECIFIED",			"REV_KEYCOMPROMISE",	"REV_CACOMPROMISE",
		"REV_AFFILIATIONCHANGED",	"REV_SUPERSEDED",		"REV_CESSATIONOFOPERATION",
		"REV_CERTIFICATEHOLD",		"REV_REMOVEFROMCRL",	"REV_PRIVILEGEWITHDRAWN",
		"REV_AACOMPROMISE"};
	
    protected static final String RESPONDWITH_X509CERT           = "X509CERT";
    protected static final String RESPONDWITH_X509CHAIN          = "X509CHAIN";
    protected static final String RESPONDWITH_X509CHAINANDCRL    = "X509CHAINANDCRL";
    
    protected static final String ENCODING_PEM        = "pem";
    protected static final String ENCODING_DER        = "der";
    protected static final String ENCODING_P12        = "p12";
    protected static final String ENCODING_JKS        = "jks";
    
    protected static final String KEYUSAGE_ALL                  = "ALL";
    protected static final String KEYUSAGE_SIGNATURE            = "SIGNATURE";
    protected static final String KEYUSAGE_ENCRYPTION           = "ENCRYPTION";
    protected static final String KEYUSAGE_EXCHANGE             = "EXCHANGE";
    
    protected static final String QUERYTYPE_CERT               = "CERT";			
    protected static final String QUERYTYPE_SMIME              = "SMIME";	
    protected static final String QUERYTYPE_TLS                = "TLS";
    protected static final String QUERYTYPE_TLSHTTP            = "TLSHTTP";
    protected static final String QUERYTYPE_TLSSMTP            = "TLSSMTP";
    protected static final String QUERYTYPE_IPSEC              = "IPSEC";
    protected static final String QUERYTYPE_PKIX               = "PKIX";
	
	protected static final int[] REASON_VALUES = {RevokedCertInfo.NOT_REVOKED, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, 
		RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE,
		RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED, RevokedCertInfo.REVOCATION_REASON_SUPERSEDED,
		RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
		RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL, RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN,
		RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE};
	
	XKMSCLIBaseCommand(String[] args){
		CryptoProviderTools.installBCProvider();
		this.args = args;
	}
	
	/**
	 * Method creating a connection to the webservice
	 * using the information stored in the property files.
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
	protected XKMSInvoker getXKMSInvoker() throws FileNotFoundException, IOException {       
		if (xkms == null) {
			if (getKeyStorePath()!=null) {
				try{
					KeyStore clientKeyStore = KeyStore.getInstance("JKS");				  
					clientKeyStore.load(new FileInputStream(getKeyStorePath()), getKeyStorePassword().toCharArray());
					if (getKeyStoreAlias() == null) {
						throw new IOException("Error no alias specified in the property file");
					}
					String alias = getKeyStoreAlias();       
					clientCert = (java.security.cert.X509Certificate)clientKeyStore.getCertificate(alias);            
					privateKey = clientKeyStore.getKey(alias, getKeyStorePassword().toCharArray());
					Certificate[] trustedcerts = clientKeyStore.getCertificateChain(alias);
					catrustlist = new ArrayList<Certificate>();
					for (int i=0;i<trustedcerts.length;i++ ) {
						if(((X509Certificate)trustedcerts[i]).getBasicConstraints() != -1){
							catrustlist.add(trustedcerts[i]);
						}
					}
				} catch(Exception e) {
					throw new IOException("Error reading client keystore " + e.getMessage());
				}			      
			}
			xkms = new XKMSInvoker(getWebServiceURL(),catrustlist);
		}
		return xkms;
	}

	private String getKeyStorePassword() throws FileNotFoundException, IOException {
		final String CONF_KEYSTORE_PASSWORD = "xkmscli.keystore.password";
		if(password == null){
			if(getProperties().getProperty(CONF_KEYSTORE_PASSWORD) == null){
			   BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			   System.out.print("Enter keystore password :");
			   password = reader.readLine();
			}else{
				password = getProperties().getProperty(CONF_KEYSTORE_PASSWORD);
				if (log.isDebugEnabled()) {
					log.debug(CONF_KEYSTORE_PASSWORD + ": <set in config file>");
				}
			}
		}
		return password;
	}

	private String getKeyStorePath() throws FileNotFoundException, IOException {
		final String CONF_KEYSTORE_PATH = "xkmscli.keystore.path";
		String value = getProperties().getProperty(CONF_KEYSTORE_PATH);
		if (log.isDebugEnabled()) {
			log.debug(CONF_KEYSTORE_PATH + ": " + value);
		}
		return value;
	}

	private String getKeyStoreAlias() throws FileNotFoundException, IOException {
		final String CONF_KEYSTORE_ALIAS = "xkmscli.keystore.alias";
		String value = getProperties().getProperty(CONF_KEYSTORE_ALIAS);
		if (log.isDebugEnabled()) {
			log.debug(CONF_KEYSTORE_ALIAS + ": " + value);
		}
		return value;
	}
	
	private String getWebServiceURL() throws FileNotFoundException, IOException {	
		return getProperties().getProperty("xkmscli.url", "http://localhost:8080/ejbca/xkms/xkms");
	}

	private Properties getProperties() throws FileNotFoundException, IOException  {
		if(props == null){
		  props  = new Properties();
		  try {
			props.load(new FileInputStream("xkmscli.properties"));
		  } catch (FileNotFoundException e) {
			// Try in parent directory
			props.load(new FileInputStream("../xkmscli.properties"));
		  }
		}
		return props;
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
	
	protected String genId() throws NoSuchAlgorithmException {
        BigInteger serno = null;		
        Random random = SecureRandom.getInstance("SHA1PRNG");

        long seed = Math.abs((new Date().getTime()) + this.hashCode());
        random.setSeed(seed);
		try {
	        byte[] sernobytes = new byte[8];

	        random.nextBytes(sernobytes);
	        serno = (new java.math.BigInteger(sernobytes)).abs();
	       
		} catch (Exception e) {
			getPrintStream().println("Error generating response ID " );
		}
		return "_" + serno.toString();
	}
	
	/**
     * Returns a collection of resonswith tags.
     * 
     * @param arg
     * @return a collection of Strings containging respond with constatns
     */
    protected Collection<String> getResponseWith(String arg) {
    	ArrayList<String> retval = new ArrayList<String>();
		
    	if(arg.equalsIgnoreCase(RESPONDWITH_X509CERT)){
    		retval.add(XKMSConstants.RESPONDWITH_X509CERT);
    		return retval;
    	}

    	if(arg.equalsIgnoreCase(RESPONDWITH_X509CHAIN)){
    		retval.add(XKMSConstants.RESPONDWITH_X509CHAIN);
    		return retval;
    	}
    	
    	if(arg.equalsIgnoreCase(RESPONDWITH_X509CHAINANDCRL)){
    		retval.add(XKMSConstants.RESPONDWITH_X509CHAIN);
    		retval.add(XKMSConstants.RESPONDWITH_X509CRL);
    		return retval;
    	}
    	
		getPrintStream().println("Illegal response with " + arg);
        usage();
    	System.exit(-1); // NOPMD, this is not a JEE app
		return null;
	}
	
	/**
     * Method that loads a certificate from file 
     * @param filename
     * @return
     */
    protected byte[] loadCert(String arg) {
		try {
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(arg));
            try {
                byte[] retval = new byte[bis.available()];
                bis.read(retval);
                return retval;
            } finally {
                bis.close();
            }
			
		} catch (FileNotFoundException e) {
			getPrintStream().println("Couldn't find file with name " + arg);
	        usage();
	    	System.exit(-1); // NOPMD, this is not a JEE app
		} catch (IOException e) {
			getPrintStream().println("Couldn't read file with name " + arg);
	        usage();
	    	System.exit(-1); // NOPMD, this is not a JEE app
		}
		return null;
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
	
	protected void displayKeyUsage(UnverifiedKeyBindingType next) {
		Iterator<String> iter = next.getKeyUsage().iterator();
		getPrintStream().println("  Certificate have the following key usage:");
		if(next.getKeyUsage().size() == 0){
			getPrintStream().println("    " + KEYUSAGE_ALL );
		}
		while(iter.hasNext()){
			String keyUsage = iter.next();
			if(keyUsage.equals(XKMSConstants.KEYUSAGE_SIGNATURE)){
				getPrintStream().println("    " + KEYUSAGE_SIGNATURE );				
			}
			if(keyUsage.equals(XKMSConstants.KEYUSAGE_ENCRYPTION)){
				getPrintStream().println("    " + KEYUSAGE_ENCRYPTION);				
			}
			if(keyUsage.equals(XKMSConstants.KEYUSAGE_EXCHANGE)){
				getPrintStream().println("    " + KEYUSAGE_EXCHANGE);				
			}
		}				
		
	}
	


	protected void displayUseKeyWith(UnverifiedKeyBindingType next) {
		Iterator<UseKeyWithType> iter = next.getUseKeyWith().iterator();
		if(next.getKeyUsage().size() != 0){
			getPrintStream().println("  Certificate can be used with applications:");
			while(iter.hasNext()){
				UseKeyWithType useKeyWith = iter.next();
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_IPSEC)){
					getPrintStream().println("    " + QUERYTYPE_IPSEC + " = " + useKeyWith.getIdentifier());				
				}
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_PKIX)){
					getPrintStream().println("    " + QUERYTYPE_PKIX + " = " + useKeyWith.getIdentifier());				
				}
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_SMIME)){
					getPrintStream().println("    " + QUERYTYPE_SMIME + " = " + useKeyWith.getIdentifier());				
				}
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_TLS)){
					getPrintStream().println("    " + QUERYTYPE_TLS + " = " + useKeyWith.getIdentifier());				
				}
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_TLSHTTP)){
					getPrintStream().println("    " + QUERYTYPE_TLSHTTP + " = " + useKeyWith.getIdentifier());				
				}
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_TLSSMTP)){
					getPrintStream().println("    " + QUERYTYPE_TLSSMTP + " = " + useKeyWith.getIdentifier());				
				}
			}
		}
	}
	
	   /**
     * Stores keystore.
     *
     * @param ks         KeyStore
     * @param username   username, the owner of the keystore
     * @param kspassword the password used to protect the peystore
     * @param createJKS  if a jks should be created
     * @param createPEM  if pem files should be created
     * @throws IOException if directory to store keystore cannot be created
     */
    protected void storeKeyStore(KeyStore ks, String username, String kspassword, boolean createJKS,
                               boolean createPEM, String mainStoreDir)
            throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, CertificateException {       

        // Where to store it?
        if (mainStoreDir == null) {
            throw new IOException("Can't find directory to store keystore in.");
        }

        String keyStoreFilename = mainStoreDir  + username;

        if (createJKS) {
            keyStoreFilename += ".jks";
        } else {
            keyStoreFilename += ".p12";
        }

        // If we should also create PEM-files, do that
        if (createPEM) {
            String PEMfilename = mainStoreDir + "pem";
            P12toPEM p12topem = new P12toPEM(ks, kspassword);
            p12topem.setExportPath(PEMfilename);
            p12topem.createPEM();
            getPrintStream().println("Keystore written successfully to the directory " + PEMfilename);
        } else {
            FileOutputStream os = new FileOutputStream(keyStoreFilename);
            ks.store(os, kspassword.toCharArray());
            getPrintStream().println("Keystore written successfully to " + keyStoreFilename);
        }
        
        

    } // storeKeyStore
	
	protected void displayStatus(KeyBindingType type) {
		StatusType status = type.getStatus();
		getPrintStream().println("  The certificate had the following status");
		getPrintStream().println("  Valid:");
		displayStatusReasons(status.getValidReason());
		getPrintStream().println("  Indeterminable:");
		displayStatusReasons(status.getIndeterminateReason());
		getPrintStream().println("  Invalid:");
		displayStatusReasons(status.getInvalidReason());
		
	}

	private void displayStatusReasons(List<String> reasons) {
		if(reasons.size() == 0){
			getPrintStream().println("      NONE");
		}else{
			Iterator<String> iter = reasons.iterator();
			while(iter.hasNext()){
				String next = iter.next();
				if(next.equals(XKMSConstants.STATUSREASON_ISSUERTRUST)){
					getPrintStream().println("      ISSUERTRUST");
				}
				if(next.equals(XKMSConstants.STATUSREASON_REVOCATIONSTATUS)){
					getPrintStream().println("      REVOCATIONSTATUS");
				}
				if(next.equals(XKMSConstants.STATUSREASON_SIGNATURE)){
					getPrintStream().println("      SIGNATURE");
				}
				if(next.equals(XKMSConstants.STATUSREASON_VALIDITYINTERVAL)){
					getPrintStream().println("      VALIDITYINTERVAL");
				}
			}
		}
	}

	protected List<X509Certificate> getCertsFromKeyBinding(KeyBindingType keyBinding) throws CertificateException {
		List<X509Certificate> retval = new ArrayList<X509Certificate>();
		
		@SuppressWarnings("unchecked")
        JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBinding.getKeyInfo().getContent().get(0);		
		Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
		while(iter2.hasNext()){
			JAXBElement<?> next = (JAXBElement<?>) iter2.next();					
			if(next.getName().getLocalPart().equals("X509Certificate")){
			  byte[] encoded = (byte[]) next.getValue();
			  X509Certificate nextCert =  (X509Certificate) CertTools.getCertfromByteArray(encoded);
			  retval.add(nextCert);
			}
		}	
		
		return retval;
	}


	protected abstract void usage();

}
