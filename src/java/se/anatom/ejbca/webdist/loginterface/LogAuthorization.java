package se.anatom.ejbca.webdist.loginterface;

import java.io.Serializable;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;

/**
 * A class that looks up the which modules a administrator have right to view.
 * This is done by looking up an administrators privileges in the tree and returning a string to be used in SQL-queries.
 * 
 * @version $Id: LogAuthorization.java,v 1.3 2003-01-12 17:16:20 anatom Exp $
 */
public class LogAuthorization implements Serializable {
    
  
    
    /** Creates a new instance of LogAuthorization. */
    public LogAuthorization(EjbcaWebBean ejbcawebbean) {
       this.ejbcawebbean = ejbcawebbean;
       init();
    }

    
    
    /**
     * Method that checks the administrators view log privileges to the different modules and returns a string that should be used in where clause of SQL queries.
     *
     * @return a string of log module privileges that should be used in the where clause of SQL queries.
     */
    public String getViewLogRights() {      
      return querystring; 
    }    
        
        
    private void init()  {    
      boolean first = true;
      boolean authorized = false;
        
      for(int i = 0 ; i < LogEntry.MODULETEXTS.length; i++){
         authorized = false; 
         String resource = GlobalConfiguration.LOGMODULERESOURCES[i];
         try{ 
           authorized = ejbcawebbean.isAuthorizedNoLog(resource);
         }catch(AuthorizationDeniedException e){} 
         if(authorized){
           if(first){
             querystring = "(";
             first = false;
           }
           else
             querystring += " OR ";
             
           querystring += "module=" + i;
         }  
       }
       
       if(!querystring.equals(""))
        querystring += ")";
    }
 
    // Private fields.
    private String querystring = "";
    private EjbcaWebBean ejbcawebbean;  

}


