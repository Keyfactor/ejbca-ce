package se.anatom.ejbca.webdist.webconfiguration;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;

/**
 * A class handling the saving and loading of global configuration data.
 * By default all data are saved to a database.
 *
 * @author  Philip Vendil
 * @version $Id: GlobalConfigurationDataHandler.java,v 1.16 2003-09-04 14:38:11 herrvendil Exp $
 */
public class GlobalConfigurationDataHandler {

    /** Creates a new instance of GlobalConfigurationDataHandler */
    public GlobalConfigurationDataHandler(Admin administrator,IRaAdminSessionLocal raadminsession, IAuthorizationSessionLocal authorizationsession){
      this.raadminsession = raadminsession;
      this.authorizationsession = authorizationsession;
      this.administrator = administrator;
    }

    public GlobalConfiguration loadGlobalConfiguration() throws NamingException{
        GlobalConfiguration ret = null;

        ret = raadminsession.loadGlobalConfiguration(administrator);
        InitialContext ictx = new InitialContext();
        Context myenv = (Context) ictx.lookup("java:comp/env");      
        ret.initialize((String) myenv.lookup("BASEURL"), (String) myenv.lookup("ADMINDIRECTORY"),
                        (String) myenv.lookup("AVAILABLELANGUAGES"), (String) myenv.lookup("AVAILABLETHEMES"), 
                        (String) myenv.lookup("PUBLICPORT"),(String) myenv.lookup("PRIVATEPORT"),
                        (String) myenv.lookup("PUBLICPROTOCOL"),(String) myenv.lookup("PRIVATEPROTOCOL"));
        return ret;
    }

    public void saveGlobalConfiguration(GlobalConfiguration gc) throws AuthorizationDeniedException {
       if(this.authorizationsession.isAuthorizedNoLog(administrator, "/super_administrator"));
         raadminsession.saveGlobalConfiguration(administrator,  gc);
    }

   // private IRaAdminSessionHome  raadminsessionhome;
    private IRaAdminSessionLocal raadminsession;
    private IAuthorizationSessionLocal  authorizationsession;
    private Admin administrator;
}
