package se.anatom.ejbca.webdist.loginterface;

import java.io.Serializable;
import java.util.Iterator;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.AvailableAccessRules;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.LogEntry;

/**
 * A class that looks up the which modules a administrator have right to view.
 * This is done by looking up an administrators privileges in the tree and returning a string to be used in SQL-queries.
 * 
 * @version $Id: LogAuthorization.java,v 1.6 2003-09-04 09:49:46 herrvendil Exp $
 */
public class LogAuthorization implements Serializable {
    
  
    
    /** Creates a new instance of LogAuthorization. */
    public LogAuthorization(Admin administrator, IAuthorizationSessionLocal authorizationsession) {
       this.administrator = administrator;
       this.authorizationsession = authorizationsession;
    }

    
    
    /**
     * Method that checks the administrators view log privileges to the different modules and returns a string that should be used in where clause of SQL queries.
     *
     * @return a string of log module privileges that should be used in the where clause of SQL queries.
     */
    public String getViewLogRights() {      
      if(querystring == null){
        querystring = "";  
        boolean first = true;
        boolean authorized = false;
        
        for(int i = 0 ; i < LogEntry.MODULETEXTS.length; i++){
          authorized = false; 
          String resource = AvailableAccessRules.VIEWLOGACCESSRULES[i];
          try{ 
            authorized = this.authorizationsession.isAuthorizedNoLog(administrator,resource);
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
              
      return querystring; 
    } 
    
    /**
     * Method that checks the administrators view log privileges to the different CAs and returns a string that should be used in where clause of SQL queries.
     *
     * @return a string of log module privileges that should be used in the where clause of SQL queries.
     */
    public String getCARights(){
      if(caidstring == null){
        caidstring = "";
        
        Iterator iter = this.authorizationsession.getAuthorizedCAIds(administrator).iterator();
         
        try{ 
          this.authorizationsession.isAuthorizedNoLog(administrator, "/super_administrator");
          caidstring = " caid = " + ILogSessionLocal.INTERNALCAID;       
        }catch(AuthorizationDeniedException e){} 
      
        
        while(iter.hasNext()){
          if(caidstring.equals(""))
            caidstring = " caid = " + ((Integer) iter.next()).toString();   
          else    
            caidstring = caidstring + " OR caid = " + ((Integer) iter.next()).toString(); 
        }                
          
      }  
      return caidstring;   
    }
    
    public void clear(){
      this.querystring = null;
      this.caidstring = null;
    }
    
        
 
    
    
    // Private fields.
    private String querystring = null;
    private String caidstring = null;
    private IAuthorizationSessionLocal authorizationsession;
    private Admin administrator;

}


