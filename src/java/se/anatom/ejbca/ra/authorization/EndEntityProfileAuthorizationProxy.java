package se.anatom.ejbca.ra.authorization;

import java.util.HashMap;
import java.io.Serializable;
import java.rmi.RemoteException;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.log.Admin;
import javax.ejb.*;
import javax.naming.*;

import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.LogEntry;

/**
 * A class used to improve performance by proxying a users end entity profile authorization minimizing the need of traversing
 * trough the authorization tree and rmi lookups. It's use should only be within short time to avoid desyncronisation.
 *
 * @author  TomSelleck
 */
public class EndEntityProfileAuthorizationProxy implements Serializable {

    // Public Constants.
    /* Constants specifying the kind user access rights to look for, */
    public static final String VIEW_RIGHTS           = GlobalConfiguration.VIEW_RIGHTS;
    public static final String EDIT_RIGHTS           = GlobalConfiguration.EDIT_RIGHTS;
    public static final String CREATE_RIGHTS         = GlobalConfiguration.CREATE_RIGHTS;
    public static final String DELETE_RIGHTS         = GlobalConfiguration.DELETE_RIGHTS;
    public static final String REVOKE_RIGHTS         = GlobalConfiguration.REVOKE_RIGHTS;
    public static final String HISTORY_RIGHTS        = GlobalConfiguration.HISTORY_RIGHTS;
    public static final String HARDTOKEN_VIEW_RIGHTS = GlobalConfiguration.HARDTOKEN_RA_ENDING;
    public static final String KEYRECOVERY_RIGHTS    = GlobalConfiguration.KEYRECOVERYRESOURCE;    
    
    /** Creates a new instance of ProfileAuthorizationProxy. */
    public EndEntityProfileAuthorizationProxy(IAuthorizationSessionRemote authorizationsession) {
              // Get the RaAdminSession instance.
       profileauthstore = new HashMap();
       this.local=false;
       this.authorizationsessionremote = authorizationsession;
    }

    public EndEntityProfileAuthorizationProxy(IAuthorizationSessionLocal authorizationsession) {
              // Get the RaAdminSession instance.
       profileauthstore = new HashMap();
       this.local=true;
       this.authorizationsessionlocal = authorizationsession;
    }


    /**
     * Method that first tries to authorize a users profile right in local hashmap and if it doesn't exists looks it up over RMI.
     *
     * @param profileid the profile to look up.
     * @param rights which profile rights to look for.
     * @return the profilename or null if no profilename is relatied to the given id
     */
    public boolean getEndEntityProfileAuthorization(Admin admin, int profileid, String rights, int module) throws RemoteException {
      return isAuthorized(admin,profileid,rights,true,module);
    }

    /**
     * Method that first tries to authorize a users profile right in local hashmap and if it doesn't exists looks it up over RMI, without
     * performing any logging.
     *
     *
     * @param profileid the profile to look up.
     * @param rights which profile rights to look for.
     * @return the profilename or null if no profilename is relatied to the given id
     */
    public boolean getEndEntityProfileAuthorizationNoLog(Admin admin, int profileid, String rights) throws RemoteException {
      return isAuthorized(admin,profileid,rights,false, 0);
    }

    // Private Methods
    public boolean isAuthorized(Admin admin, int profileid, String rights, boolean log, int module) throws RemoteException {
      Boolean returnval = null;
      String resource= null;
      String adm = null;
      if(admin.getAdminInformation().isSpecialUser()){
        adm = Integer.toString(admin.getAdminInformation().getSpecialUser());
        // Temporary VERY UGLY
        return true;
      }
      else
        adm = new String(admin.getAdminInformation().getX509Certificate().getSignature());
      resource = adm + GlobalConfiguration.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights;
        // Check if name is in hashmap
      returnval = (Boolean) profileauthstore.get(resource);

      if(returnval != null && log){
        if(returnval.booleanValue()){
            getLogSessionBean().log(admin, module, new java.util.Date(),null, null, LogEntry.EVENT_INFO_AUTHORIZEDTORESOURCE,
                                    "Resource : " + GlobalConfiguration.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights);
        }else{
            getLogSessionBean().log(admin, module, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,
                                    "Resource : " + GlobalConfiguration.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights);
        }
      }

      if(returnval==null){
        // Retreive profilename over RMI
        try{
          if(local){
            if(log)
              authorizationsessionlocal.isAuthorized(admin.getAdminInformation(),GlobalConfiguration.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights);
            else
              authorizationsessionlocal.isAuthorizedNoLog(admin.getAdminInformation(),GlobalConfiguration.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights);
          }else{
            if(log)
              authorizationsessionremote.isAuthorized(admin.getAdminInformation(),GlobalConfiguration.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights);
            else
              authorizationsessionremote.isAuthorizedNoLog(admin.getAdminInformation(),GlobalConfiguration.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights);
          }
          returnval = Boolean.TRUE;
        }catch(AuthorizationDeniedException e){
          returnval = Boolean.FALSE;
        }
        profileauthstore.put(resource,returnval);
      }

      return returnval.booleanValue();
    }

    private ILogSessionRemote getLogSessionBean() throws RemoteException {
      if(logsession == null){
        try{
          jndicontext = new InitialContext();
          ILogSessionHome logsessionhome = (ILogSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("java:comp/env/ejb/LogSession"),ILogSessionHome.class);
          logsession = logsessionhome.create();
        }catch(Exception e){
           throw new EJBException(e.getMessage());
        }
      }
      return logsession;
    }

    // Private fields.
    private boolean                     local = false;
    private InitialContext              jndicontext;
    private HashMap                     profileauthstore;
    private IAuthorizationSessionRemote authorizationsessionremote;
    private IAuthorizationSessionLocal  authorizationsessionlocal;
    private ILogSessionRemote           logsession;

}
