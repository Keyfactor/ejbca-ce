package se.anatom.ejbca.log;

import java.rmi.*;
import java.io.*;
import java.util.Date;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Properties;
import java.sql.*;
import javax.sql.DataSource;
import javax.naming.*;
import javax.ejb.*;
import java.lang.reflect.Method;
import java.security.cert.X509Certificate;

import org.apache.log4j.*;
import RegularExpression.RE;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.util.query.*;


/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalLogSessionBean.java,v 1.1 2002-09-12 17:12:13 herrvendil Exp $
 */
public class LocalLogSessionBean extends BaseSessionBean  {

    private static Category cat = Category.getInstance(LocalLogSessionBean.class.getName());
    
    public static final int MAXIMUM_QUERY_ROWCOUNT = 500;

    /** Var holding JNDI name of datasource */
    private String dataSource = "java:/DefaultDS";

    /** The home interface of  LogEntryData entity bean */
    private LogEntryDataLocalHome logentryhome=null;

    /** The home interface of  LogConfigurationData entity bean */
    private LogConfigurationDataLocalHome logconfigurationhome=null;
    
    /** The remote interface of the LogConfigurationData entity bean */
    private LogConfigurationDataLocal logconfigurationdata=null;

    /** The logconfiguration data, store for performance */
    private LogConfiguration logconfiguration;
    
    /** Collection of available log devices, i.e Log4j etc */
    private ArrayList logdevices = null;
    
    private static final int LOGCONFIGURATION_ID = 0; 
    
    /** Columns in the database used in select */
    private final String LOGENTRYDATA_COL = "adminType, adminData, time, username, certificateSNR, event, comment";    
    
    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */    
    public void ejbCreate() throws Exception {
        debug(">ejbCreate()");
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);

        logentryhome = (LogEntryDataLocalHome)lookup("java:comp/env/ejb/LogEntryDataLocal", LogEntryDataLocalHome.class);
        logconfigurationhome = (LogConfigurationDataLocalHome)lookup("java:comp/env/ejb/LogConfigurationDataLocal", LogConfigurationDataLocalHome.class);
          
        // Check if log configuration exists, else create one.
        loadLogConfiguration();
               
        // Setup Connection to signing devices.
        logdevices = new ArrayList();
        
        // Get configuration of log device classes from ejb-jar.xml
        String factoryclassesstring = (String)lookup("java:comp/env/logDeviceFactories", java.lang.String.class);
        String propertyfilesstring  = (String)lookup("java:comp/env/logDevicePropertyFiles", java.lang.String.class);
        
        String[] factoryclasses = new RE(";", false).split(factoryclassesstring); 
        String[] propertyfiles  = new RE(";", false).split(propertyfilesstring);
        
        Properties[] properties = new Properties[propertyfiles.length];
        for(int i= 0; i < propertyfiles.length; i++){  
            properties[i] =  new Properties();            
            if(!(propertyfiles[i] == null || propertyfiles[i].trim().equals("")))
              properties[i].load(this.getClass().getResourceAsStream("/logdeviceproperties/" + propertyfiles[i].trim()));
        }
        
        for(int i=0; i < factoryclasses.length; i++){
            Class implClass = Class.forName( factoryclasses[i].trim() );
            Object fact = implClass.newInstance();     
            Class[] paramTypes = new Class[1];
            paramTypes[0] = properties[0].getClass();            
            Method method = implClass.getMethod("makeInstance", paramTypes);            
            Object[] params = new Object[1];
            if(i < properties.length)
              params[0] = properties[i];
            else
              params[0] = new Properties();
            logdevices.add((ILogDevice)method.invoke(fact, params)); 
        }
        debug("<ejbCreate()");
    }


    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection
    
    /**
     * Session beans main function. Takes care of the logging functionality.
     *
     * @param admin the administrator performing the event.
     * @param time the time the event occured.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the se.anatom.ejbca.log.LogEntry.EVENT_ constants.
     * @param comment comment of the event.
     */
    public void log(Admin admin, Date time, String username, X509Certificate certificate, int event, String comment){
      try{               
        // Get logging configuration  
        if(logconfiguration.logEvent(event)){
          if(logconfiguration.useLogDB()){
             // Log to the local database.
             if(certificate != null)                      
               logentryhome.create(logconfigurationdata.getAndIncrementRowCount(), admin.getAdminType(), admin.getAdminData(),time, username,
                                   certificate.getSerialNumber().toString(16), event, comment); 
             else 
               logentryhome.create(logconfigurationdata.getAndIncrementRowCount(), admin.getAdminType(), admin.getAdminData(),time, username,
                                   null, event, comment);               
          }    
          if(logconfiguration.useExternalLogDevices()){
            // Log to external devices. I.e Log4j etc 
            Iterator i = logdevices.iterator();
            while(i.hasNext()){
               ((ILogDevice) i.next()).log(admin, time, username, certificate, event, comment);   
            }              
          }
        } 
      }catch(Exception e){
        throw new EJBException(e);   
      }
   
    } // log
    
    /**
     * Method to execute a customized query on the log db data. The parameter query should be a legal Query object.
     * 
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @return a collection of LogEntry. Maximum size of Collection is defined i ILogSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @see se.anatom.ejbca.util.query.Query 
     */
    public Collection query(Query query) throws IllegalQueryException{
        debug(">query()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();
        
        // Check if query is legal.
        if(!query.isLegalQuery()) 
          throw new IllegalQueryException();
        try{
           // Construct SQL query.            
            con = getConnection();
            ps = con.prepareStatement("select " + LOGENTRYDATA_COL + " from LogEntryData where " + query.getQueryString() );
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.            
            while(rs.next() && returnval.size() <= MAXIMUM_QUERY_ROWCOUNT){
              LogEntry data = new LogEntry(rs.getInt(1), rs.getString(2), new java.util.Date(rs.getLong(3)), rs.getString(4), rs.getString(5)
                                               , rs.getInt(6), rs.getString(7));   
              returnval.add(data); 
            }
            debug("<query()");  
            return returnval;
            
        }catch(Exception e){
          throw new EJBException(e);   
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
              se.printStackTrace();   
           }
        }       
    } // query
    
    /**
     * Loads the log configuration from the database.
     *
     * @return the logconfiguration
     */
    public LogConfiguration loadLogConfiguration(){
        // Check if log configuration exists, else create one.
      try{
        logconfigurationdata = logconfigurationhome.findByPrimaryKey(new Integer(LOGCONFIGURATION_ID));
        logconfiguration = logconfigurationdata.loadLogConfiguration();
      }catch(FinderException e){
         try{ 
           logconfiguration = new LogConfiguration();
           logconfigurationdata = logconfigurationhome.create(new Integer(LOGCONFIGURATION_ID),logconfiguration);
         }catch(CreateException f){
           throw new EJBException(f);
         }  
      }      
        
      return logconfiguration;  
    } // loadLogConfiguration
    
    /**
     * Saves the log configuration to the database.
     *
     * @param logconfiguration the logconfiguration to save.
     */    
    public void saveLogConfiguration(Admin admin, LogConfiguration logconfiguration){
      this.logconfiguration = logconfiguration;  
      try{  
        try{
          (logconfigurationhome.findByPrimaryKey(new Integer(LOGCONFIGURATION_ID))).saveLogConfiguration(logconfiguration);
          log(admin, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITLOGCONFIGURATION,"");            
        }catch(FinderException e){          
           logconfigurationhome.create(new Integer(LOGCONFIGURATION_ID),logconfiguration);
           log(admin, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITLOGCONFIGURATION,"");             
        }
      }catch(Exception e){
            log(admin, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITLOGCONFIGURATION,"");  
         throw new EJBException(e);   
      }
    } // saveLogConfiguration
    
} // LocalLogSessionBean

