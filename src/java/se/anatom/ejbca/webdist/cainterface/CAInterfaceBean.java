/*
 * CaInterfaceBean.java
 *
 * Created on den 7 maj 2002, 12:06
 */

package se.anatom.ejbca.webdist.cainterface;

import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import java.util.Properties;
import java.util.Collection;
import java.io.FileInputStream;
import java.rmi.RemoteException;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.CertificateDataPK;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.CertificateDataHome;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.IJobRunnerSessionHome;

import se.anatom.ejbca.webdist.rainterface.CertificateView; 
import se.anatom.ejbca.webdist.rainterface.RevokedInfoView;
import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;

/**
 * A class used as an interface between CA jsp pages and CA ejbca functions.
 * @author  Philip Vendil
 */
public class CAInterfaceBean {
    
    /** Creates a new instance of CaInterfaceBean */
    public CAInterfaceBean() throws IOException, FileNotFoundException, NamingException, CreateException {
         // Get the UserSdminSession instance.
      Properties jndienv = new Properties();
      jndienv.load(this.getClass().getResourceAsStream("/WEB-INF/jndi.properties"));
      jndicontext = new InitialContext(jndienv);

      Object obj1 = jndicontext.lookup("CertificateStoreSession");
      certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
      certificatesession = certificatesessionhome.create();       
    }
    
    // Public methods
    public CertificateView[] getCAInfo() throws RemoteException, NamingException, CreateException {
      CertificateView[] returnval = null;  
      ISignSessionHome home = (ISignSessionHome)javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RSASignSession"), ISignSessionHome.class );
      ISignSessionRemote ss = home.create();
      Certificate[] chain = ss.getCertificateChain();
            
      if(chain != null){
        returnval = new CertificateView[chain.length];  
        for(int i = 0; i < chain.length; i++){
          RevokedInfoView revokedinfo = null;
          RevokedCertInfo revinfo = certificatesession.isRevoked(((X509Certificate) chain[i]).getIssuerDN().toString(), ((X509Certificate) chain[i]).getSerialNumber());
          if(revinfo != null)
            revokedinfo = new RevokedInfoView(revinfo);   
          returnval[i] = new CertificateView((X509Certificate) chain[i], revokedinfo);   
        }
      }
        
      return returnval;
    }
        
    public void createCRL()  throws RemoteException, NamingException, CreateException  {
      IJobRunnerSessionHome home  = (IJobRunnerSessionHome)javax.rmi.PortableRemoteObject.narrow( jndicontext.lookup("CreateCRLSession") , IJobRunnerSessionHome.class );
      home.create().run();      
    }
        
    public int getLastCRLNumber() throws RemoteException  {
      return certificatesession.getLastCRLNumber();  
    }
    
    
    // Private methods
    
    // Private fields
    private InitialContext                     jndicontext; 
    private ICertificateStoreSessionRemote     certificatesession; 
    private ICertificateStoreSessionHome       certificatesessionhome;   
    
}
