/*
 * ApplyBean.java
 *
 * Created on den 3 nov 2002, 12:06
 */

package se.anatom.ejbca.apply;

import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;

import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.SecConst;

/**
 * A class used as an interface between Apply jsp pages and ejbca functions.
 *
 * @author  Philip Vendil
 * @version $Id: ApplyBean.java,v 1.2 2002-11-13 12:23:39 anatom Exp $
 */
public class ApplyBean   {

    /** Creates a new instance of CaInterfaceBean */
    public ApplyBean() {
    }

    // Public methods
    public void initialize(HttpServletRequest request) throws  Exception{
      if(!initialized){
        if( request.getAttribute( "javax.servlet.request.X509Certificate" ) != null)
          administrator = new Admin(((X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" ))[0]);
        else
           administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
        InitialContext jndicontext = new InitialContext();
        Object obj1 = jndicontext.lookup("UserAdminSession");
        useradminhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
        obj1 = jndicontext.lookup("CertificateStoreSession");
        certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        initialized =true;
      }
    }

    /** Method that returns a users tokentype defined in SecConst, if 0 is returned user couldn't be found i database. */
    public int getTokenType(String username) throws Exception{
      int returnval =0;
      UserAdminData userdata = null;
      IUserAdminSessionRemote useradminsession = useradminhome.create(administrator);
      try{
        userdata = useradminsession.findUser(username);
      }catch(FinderException fe){}
      if(userdata != null)
        returnval = userdata.getTokenType();

      return returnval;
    }

    /** Method that returns a bitlengths available for the user. Returns null if user couldn't be found in database.*/
    public int[] availableBitLengths(String username) throws Exception {
      int[] returnval = null;
      UserAdminData userdata = null;
      IUserAdminSessionRemote useradminsession = useradminhome.create(administrator);
      try{
        userdata = useradminsession.findUser(username);
      }catch(FinderException fe){}
      if(userdata != null){
        ICertificateStoreSessionRemote certstoresession = certificatesessionhome.create(administrator);
        int certprofile = userdata.getCertificateProfileId();
        if(certprofile !=SecConst.PROFILE_NO_CERTIFICATEPROFILE){
          returnval =  certstoresession.getCertificateProfile(certprofile).getAvailableBitLengths();
        }
      }
      return returnval;
    }


    // Private methods

    // Private fields
    private IUserAdminSessionHome             useradminhome;
    private ICertificateStoreSessionHome      certificatesessionhome;
    private boolean                           initialized;
    private Admin                             administrator;
}
