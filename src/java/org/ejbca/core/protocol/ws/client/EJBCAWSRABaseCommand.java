package org.ejbca.core.protocol.ws.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URL;
import java.util.Properties;

import javax.xml.namespace.QName;

import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.util.CertTools;

/**
 * Base class inherited by all EJBCA RA WS cli commands.
 * Checks the property file and creates a webservice connection.
 *  
 * @author Philip Vendil
 * $Id$
 */

public abstract class EJBCAWSRABaseCommand {
	
	protected String[] args = null;
	private org.ejbca.core.protocol.ws.client.gen.EjbcaWS ejbcaraws = null;
	private Properties props = null;
	private String password = null;
	
	
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
	
	EJBCAWSRABaseCommand(String[] args){
		this.args = args;
	}
	
	/**
	 * Method creating a connection to the webservice
	 * using the information stored in the property files.
     * If a connection allready is establiched this connection will be used
	 * @throws ServiceException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
    protected EjbcaWS getEjbcaRAWS() throws  FileNotFoundException, IOException{
        return getEjbcaRAWS(false);
    }
    /**
     * Method creating a connection to the webservice
     * using the information stored in the property files.
     * A new connection will be created for each call.
     * @throws ServiceException 
     * @throws IOException 
     * @throws FileNotFoundException 
     */
    protected EjbcaWS getEjbcaRAWSFNewReference() throws  FileNotFoundException, IOException{
        return getEjbcaRAWS(true);
    }
    private EjbcaWS getEjbcaRAWS(boolean bForceNewReference) throws  FileNotFoundException, IOException{       
		if(ejbcaraws == null){
			CertTools.installBCProvider();
						
			File f = new File(getKeyStorePath());
			if (!f.exists()) {
				throw new IOException("Truststore '"+getKeyStorePath()+"' does not exist");
			}
			System.setProperty("javax.net.ssl.trustStore",getKeyStorePath());
			System.setProperty("javax.net.ssl.trustStorePassword",getKeyStorePassword());
			
			f = new File(getKeyStorePath());
			if (!f.exists()) {
				throw new IOException("Keystore '"+getKeyStorePath()+"' does not exist");
			}
			System.setProperty("javax.net.ssl.keyStore",getKeyStorePath());
			System.setProperty("javax.net.ssl.keyStorePassword",getKeyStorePassword());      
        }
        if(ejbcaraws==null || bForceNewReference){
			QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
			EjbcaWSService service = new EjbcaWSService(new URL(getWebServiceURL()),qname);
            if ( bForceNewReference )
                return service.getEjbcaWSPort();
            else
                ejbcaraws = service.getEjbcaWSPort();
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

	private String getWebServiceURL() throws FileNotFoundException, IOException {	
		return getProperties().getProperty("ejbcawsracli.url", "https://localhost:8443/ejbca/ejbcaws/ejbcaws") + "?wsdl";
	}

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
