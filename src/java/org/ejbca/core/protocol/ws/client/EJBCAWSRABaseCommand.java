package org.ejbca.core.protocol.ws.client;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URL;
import java.util.Properties;

import javax.xml.rpc.ServiceException;

import org.ejbca.core.protocol.ws.RevokeStatus;
import org.ejbca.core.protocol.ws.wsclient.EjbcaRAWS;
import org.ejbca.util.CertTools;

/**
 * Base class inherited by all EJBCA RA WS cli commands.
 * Checks the property file and creates a webservice connection.
 *  
 * @author Philip Vendil
 * $Id: EJBCAWSRABaseCommand.java,v 1.1 2006-09-17 23:00:25 herrvendil Exp $
 */

public abstract class EJBCAWSRABaseCommand {
	
	protected String[] args = null;
	private org.ejbca.core.protocol.ws.wsclient.EjbcaRAWSSoapBindingStub ejbcaraws = null;
	private Properties props = null;
	private String password = null;
	
	
	protected static final String[] REASON_TEXTS ={"NOT REVOKED","UNSPECIFIED","KEYCOMPROMISE","CACOMPROMISE",
		"AFFILIATIONCHANGED","SUPERSEDED","CESSATIONOFOPERATION",
		"CERTIFICATEHOLD","REMOVEFROMCRL","PRIVILEGESWITHDRAWN",
	"AACOMPROMISE"};
	
	protected static final int[] REASON_VALUES = {RevokeStatus.NOT_REVOKED,RevokeStatus.REVOKATION_REASON_UNSPECIFIED, 
		RevokeStatus.REVOKATION_REASON_KEYCOMPROMISE,RevokeStatus.REVOKATION_REASON_CACOMPROMISE,
		RevokeStatus.REVOKATION_REASON_AFFILIATIONCHANGED,RevokeStatus.REVOKATION_REASON_SUPERSEDED,
		RevokeStatus.REVOKATION_REASON_CESSATIONOFOPERATION,RevokeStatus.REVOKATION_REASON_CERTIFICATEHOLD,
		RevokeStatus.REVOKATION_REASON_REMOVEFROMCRL,RevokeStatus.REVOKATION_REASON_PRIVILEGESWITHDRAWN,
		RevokeStatus.REVOKATION_REASON_AACOMPROMISE};
	
	EJBCAWSRABaseCommand(String[] args){
		this.args = args;
	}
	
	/**
	 * Method creating a connection to the webservice
	 * using the information stored in the property files.
	 * @throws ServiceException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
	protected EjbcaRAWS getEjbcaRAWS() throws ServiceException, FileNotFoundException, IOException{       
		if(ejbcaraws == null){
			CertTools.installBCProvider();
						
			System.setProperty("javax.net.ssl.trustStore",getKeyStorePath());
			System.setProperty("javax.net.ssl.trustStorePassword",getKeyStorePassword());
			
			System.setProperty("javax.net.ssl.keyStore",getKeyStorePath());
			System.setProperty("javax.net.ssl.keyStorePassword",getKeyStorePassword());      
		


			ejbcaraws = (org.ejbca.core.protocol.ws.wsclient.EjbcaRAWSSoapBindingStub)
			new org.ejbca.core.protocol.ws.wsclient.EjbcaRAWSServiceLocator().getEjbcaRAWS(new java.net.URL("https://localhost:8443/ejbca/ejbcaws/services/EjbcaRAWS"));


	        // Time out after a minute
			ejbcaraws.setTimeout(60000);
	        
	        System.out.println(ejbcaraws.test("test1"));

		}
                
        return ejbcaraws;
        
	}

	private String getKeyStorePassword() throws FileNotFoundException, IOException {
		if(password == null){
			if(getProperties().getProperty("ejbcawsracli.keystore.password") == null){
			   BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			   System.out.print("Enter keystore password :");
			   password = reader.readLine();
			}else{
				password = getProperties().getProperty("ejbcawsracli.keystore.password");
			}
		}
		return password;
	}

	private String getKeyStorePath() throws FileNotFoundException, IOException {
		return getProperties().getProperty("ejbcawsracli.keystore.path", "keystore.jks");
	}

/*	private String getWebServiceURL() throws FileNotFoundException, IOException {	
		return getProperties().getProperty("ejbcawsracli.url", "https://localhost:8443/ejbcaraws/ejbcaraws") + "?wsdl";
	}*/

	private Properties getProperties() throws FileNotFoundException, IOException  {
		if(props == null){
		  props  = new Properties();
		  try {
			props.load(new FileInputStream("ejbcawsracli.properties"));
		  } catch (FileNotFoundException e) {
			// Try in parent directory
			props.load(new FileInputStream("../ejbcawsracli.properties"));
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
