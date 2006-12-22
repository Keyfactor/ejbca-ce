package org.ejbca.core.protocol.xkms.client;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

import javax.xml.rpc.ServiceException;

import org.ejbca.core.model.ca.crl.RevokedCertInfo;

/**
 * Base class inherited by all XKMS cli commands.
 * Checks the property file and creates a webservice connection.
 *  
 * @author Philip Vendil
 * $Id: XKMSCLIBaseCommand.java,v 1.1 2006-12-22 09:21:39 herrvendil Exp $
 */

public abstract class XKMSCLIBaseCommand {
	
	protected String[] args = null;
	private XKMSInvoker xkms = null;
	private Properties props = null;
	private String password = null;
	
	protected X509Certificate clientCert = null;
	protected Key privateKey = null;
	private Collection catrustlist = null;
	
	
	protected static final String[] REASON_TEXTS ={"NOT REVOKED","UNSPECIFIED","KEYCOMPROMISE","CACOMPROMISE",
		"AFFILIATIONCHANGED","SUPERSEDED","CESSATIONOFOPERATION",
		"CERTIFICATEHOLD","REMOVEFROMCRL","PRIVILEGESWITHDRAWN",
	"AACOMPROMISE"};
	
	public static final int NOT_REVOKED = RevokedCertInfo.NOT_REVOKED;
	public static final int REVOKATION_REASON_UNSPECIFIED = RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED;
	public static final int REVOKATION_REASON_KEYCOMPROMISE = RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE;
	public static final int REVOKATION_REASON_CACOMPROMISE = RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE;
	public static final int REVOKATION_REASON_AFFILIATIONCHANGED = RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED;
	public static final int REVOKATION_REASON_SUPERSEDED = RevokedCertInfo.REVOKATION_REASON_SUPERSEDED;
	public static final int REVOKATION_REASON_CESSATIONOFOPERATION = RevokedCertInfo.REVOKATION_REASON_CESSATIONOFOPERATION;
	public static final int REVOKATION_REASON_CERTIFICATEHOLD = RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD;
	public static final int REVOKATION_REASON_REMOVEFROMCRL = RevokedCertInfo.REVOKATION_REASON_REMOVEFROMCRL;
	public static final int REVOKATION_REASON_PRIVILEGESWITHDRAWN = RevokedCertInfo.REVOKATION_REASON_PRIVILEGESWITHDRAWN;
	public static final int REVOKATION_REASON_AACOMPROMISE = RevokedCertInfo.REVOKATION_REASON_AACOMPROMISE;
	
	protected static final int[] REASON_VALUES = {NOT_REVOKED,REVOKATION_REASON_UNSPECIFIED, 
		 REVOKATION_REASON_KEYCOMPROMISE, REVOKATION_REASON_CACOMPROMISE,
		 REVOKATION_REASON_AFFILIATIONCHANGED, REVOKATION_REASON_SUPERSEDED,
		 REVOKATION_REASON_CESSATIONOFOPERATION, REVOKATION_REASON_CERTIFICATEHOLD,
		 REVOKATION_REASON_REMOVEFROMCRL, REVOKATION_REASON_PRIVILEGESWITHDRAWN,
		 REVOKATION_REASON_AACOMPROMISE};
	
	XKMSCLIBaseCommand(String[] args){
		this.args = args;
		
	}
	
	/**
	 * Method creating a connection to the webservice
	 * using the information stored in the property files.
	 * @throws ServiceException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
	protected XKMSInvoker getXKMSInvoker() throws  FileNotFoundException, IOException{       
		if(xkms == null){
			
			  if(getKeyStorePath()!=null){
				  try{
				  KeyStore clientKeyStore = KeyStore.getInstance("JKS");				  
			      clientKeyStore.load(new FileInputStream(getKeyStorePath()), getKeyStorePassword().toCharArray());
			      if(getKeyStoreAlias() == null){
			    	  throw new IOException("Error no alias specified in the property file");
			      }
			      String alias = getKeyStoreAlias();       
			      clientCert = (java.security.cert.X509Certificate)clientKeyStore.getCertificate(alias);            
			      privateKey = clientKeyStore.getKey(alias,"foo123".toCharArray());
			      Certificate[] trustedcerts = clientKeyStore.getCertificateChain(alias);
			      catrustlist = new ArrayList();
			      for(int i=0;i<trustedcerts.length;i++ ){
			    	if(((X509Certificate)trustedcerts[i]).getBasicConstraints() != -1){
			    		catrustlist.add(trustedcerts[i]);
			    	}
			      }
				  }catch(Exception e){
					  throw new IOException("Error reading client keystore " + e.getMessage());
				  }			      
			  }
									   		
			xkms = new XKMSInvoker(getWebServiceURL(),catrustlist);

		}
                
        return xkms;
        
	}

	private String getKeyStorePassword() throws FileNotFoundException, IOException {
		if(password == null){
			if(getProperties().getProperty("xkmscli.keystore.password") == null){
			   BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			   System.out.print("Enter keystore password :");
			   password = reader.readLine();
			}else{
				password = getProperties().getProperty("xkmscli.keystore.password");
			}
		}
		return password;
	}

	private String getKeyStorePath() throws FileNotFoundException, IOException {
		return getProperties().getProperty("xkmscli.keystore.path");
	}

	private String getKeyStoreAlias() throws FileNotFoundException, IOException {
		return getProperties().getProperty("xkmscli.keystore.alias");
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
		System.exit(-1);
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
		System.exit(-1);
		return null;		
	}
	
	protected abstract void usage();

}
