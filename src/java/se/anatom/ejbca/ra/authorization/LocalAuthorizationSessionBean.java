package se.anatom.ejbca.ra.authorization;

import java.rmi.*;
import java.io.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;
import java.util.Collection;
import java.util.TreeMap;
import java.util.Set;
import java.util.Iterator;
import java.sql.*;
import javax.sql.DataSource;
import javax.naming.*;
import javax.rmi.*;
import javax.ejb.*;

import se.anatom.ejbca.BaseSessionBean;

/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalAuthorizationSessionBean.java,v 1.1 2002-06-27 10:57:34 herrvendil Exp $
 */
public class LocalAuthorizationSessionBean extends BaseSessionBean  {

    /** Var holding JNDI name of datasource */
    private String dataSource = "java:/DefaultDS";

    /** The home interface of  AvailableAccessRulesData entity bean */
    private AvailableAccessRulesDataLocalHome availableaccessruleshome = null;

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        availableaccessruleshome = (AvailableAccessRulesDataLocalHome)lookup("java:comp/env/ejb/AvailableAccessRulesDataLocal");      
        debug("<ejbCreate()");
    }

    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection
    // Methods used with AvailableAccessRulesData Entity beans.
    
    /**
     * Method to add an access rule.
     */ 

    public void addAvailableAccessRule(String name){
        debug(">addAvailableAccessRule(name : " + name + ")");
        try {
            AvailableAccessRulesDataLocal data= availableaccessruleshome.create(name);
        }
        catch (Exception e) {
        }
        debug("<addAvailableAccessRule");        
    } // addAvailableAccessRule

    /**
     * Method to add an Collection of access rules.
     */ 
    
    public void addAvailableAccessRules(Collection names){
        debug(">addAvailableAccessRules(size : " + names.size() + ")");
        if(names != null){
          Iterator i = names.iterator();
          while(i.hasNext()){
            String name = (String) i.next();
            
            try {
              AvailableAccessRulesDataLocal data= availableaccessruleshome.create(name);
            }
            catch (Exception e) {
            }
          }
        }
        debug("<addAvailableAccessRules");               
    } //  addAvailableAccessRules
 
    /**
     * Method to remove an access rule.
     */ 

    public void removeAvailableAccessRule(String name){
      debug(">removeAvailableAccessRule(name : " + name + ")");    
      try{  
        AvailableAccessRulesDataLocal data= availableaccessruleshome.findByPrimaryKey(name);      
        data.remove();
      }catch(Exception e){
      
      }
      debug("<removeAvailableAccessRule");             
    } // removeAvailableAccessRule

    /**
     * Method to remove an Collection of access rules.
     */ 
    
    public void removeAvailableAccessRules(Collection names){
      debug(">removeAvailableAccessRules(size : " + names.size() + ")");
        if(names != null){
          Iterator i = names.iterator();
          while(i.hasNext()){
            String name = (String) i.next();
            
            try{  
              AvailableAccessRulesDataLocal data= availableaccessruleshome.findByPrimaryKey(name);      
              data.remove();
            }catch(Exception e){   
            }
          }
        }
        debug("<removeAvailableAccessRules");                
    } // removeAvailableAccessRules

    /**
     * Method that returns a Collection of Strings containing all access rules.
     */ 
    
    public Collection getAvailableAccessRules(){
       Vector returnval = new Vector();
       Collection result = null;
       try{
         result = availableaccessruleshome.findAll();
       }catch(Exception e){   
       }
       if(result != null){
         Iterator i = result.iterator();
         while(i.hasNext()){
           AvailableAccessRulesDataLocal data =  (AvailableAccessRulesDataLocal) i.next();
           returnval.addElement(data.getName());
         }
       }
       java.util.Collections.sort(returnval);
       return returnval;
    } // getAvailableAccessRules
    
    /**
     * Checks wheither an access rule exists in the database.
     */ 
    
    public boolean existsAvailableAccessRule(String name){
       boolean returnval = false;
       try{
         availableaccessruleshome.findByPrimaryKey(name);   
         returnval=true;
       }catch(FinderException e){
          returnval = false;
       }
       return returnval; 
    } // existsAvailableAccessRule


    
} // LocalAvailableAccessRulesDataBean

