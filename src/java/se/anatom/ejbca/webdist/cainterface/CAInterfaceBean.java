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
import java.rmi.RemoteException;
import java.io.IOException;
import java.io.Serializable;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
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
import se.anatom.ejbca.ca.store.certificatetypes.CertificateType;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.IJobRunnerSessionHome;

import se.anatom.ejbca.webdist.rainterface.CertificateView;
import se.anatom.ejbca.webdist.rainterface.RevokedInfoView;
import se.anatom.ejbca.ra.GlobalConfiguration;


/**
 * A class used as an interface between CA jsp pages and CA ejbca functions.
 *
 * @author  Philip Vendil
 * @version $Id: CAInterfaceBean.java,v 1.6 2002-08-05 01:57:05 herrvendil Exp $
 */
public class CAInterfaceBean   {

    /** Creates a new instance of CaInterfaceBean */
    public CAInterfaceBean() throws IOException,  NamingException, CreateException, FinderException{
         // Get the UserSdminSession instance.
      InitialContext jndicontext = new InitialContext();
      Object obj1 = jndicontext.lookup("CertificateStoreSession");
      certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
      certificatesession = certificatesessionhome.create();
      
      certificatetypes = new CertificateTypeDataHandler();
    }

    // Public methods
    public CertificateView[] getCAInfo() throws RemoteException, NamingException, CreateException {
      CertificateView[] returnval = null;
      InitialContext jndicontext = new InitialContext();
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
      InitialContext jndicontext = new InitialContext();        
      IJobRunnerSessionHome home  = (IJobRunnerSessionHome)javax.rmi.PortableRemoteObject.narrow( jndicontext.lookup("CreateCRLSession") , IJobRunnerSessionHome.class );
      home.create().run();
    }

    public int getLastCRLNumber() throws RemoteException   {
      return certificatesession.getLastCRLNumber();
    }
 
    // Methods dealing with certificate types.

    public String[] getCertificateTypeNames() throws RemoteException{
      return certificatetypes.getCertificateTypeNames();
    }
    
    public int getCertificateTypeId(String certificatetypename) throws RemoteException{
      return certificatetypes.getCertificateTypeId(certificatetypename);   
    }

    /* Returns certificatetypes as a CertificateTypes object */
    public CertificateTypeDataHandler getCertificateTypeDataHandler(){
      return certificatetypes;
    }

    public CertificateType getCertificateType(String name) throws RemoteException{
      return certificatetypes.getCertificateType(name);
    }

    public void addCertificateType(String name) throws CertificateTypeExistsException, RemoteException{
       certificatetypes.addCertificateType(name, new CertificateType());
    }

    public void addCertificateType(String name, CertificateType certificatetype) throws CertificateTypeExistsException, RemoteException {
       certificatetypes.addCertificateType(name, certificatetype);
    }

    public void changeCertificateType(String name, CertificateType certificatetype) throws CertificateTypeDoesntExistsException, RemoteException {
       certificatetypes.changeCertificateType(name, certificatetype);
    }

    public void removeCertificateType(String name)throws RemoteException{
        certificatetypes.removeCertificateType(name);
    }

    public void renameCertificateType(String oldname, String newname) throws CertificateTypeExistsException, RemoteException{
       certificatetypes.renameCertificateType(oldname, newname);
    }

    public void cloneCertificateType(String originalname, String newname) throws CertificateTypeExistsException, RemoteException{
      certificatetypes.cloneCertificateType(originalname, newname);
    }
    

    // Private methods

    // Private fields
    private ICertificateStoreSessionRemote    certificatesession;
    private ICertificateStoreSessionHome      certificatesessionhome;
    private CertificateTypeDataHandler        certificatetypes;

}
