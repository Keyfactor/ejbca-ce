/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.log;

import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.Logger;


/**
 * Implements a log device using Log4j, implementes the Singleton pattern.
 *
 * @version $Id: Log4jLogDevice.java,v 1.8 2004-04-16 07:38:57 anatom Exp $
 */
public class Log4jLogDevice implements ILogDevice, java.io.Serializable {

    /** Log4j instance for Base */
    private static Logger log = Logger.getLogger(Log4jLogDevice.class);


   /**
    * A handle to the unique Singleton instance.
    */
    static private Log4jLogDevice instance = null;


   /** Initializes all internal data
    * @param prop Arguments needed for the eventual creation of the object
    */

    protected Log4jLogDevice(Properties prop) throws Exception {
       // Do nothing
    }

   /** Creates (if needed) the log device and returns the object.
    * @param prop Arguments needed for the eventual creation of the object
    * @return An instance of the log device.
    */
    static public synchronized ILogDevice instance(Properties prop) throws Exception {
       if(instance == null) {
         instance = new Log4jLogDevice(prop);
       }
       return instance;
    }

    /**
     * @see se.anatom.ejbca.log.ILogDevice
     */
    
    public void log(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment){
       String user  = "No User Involved";
       String cert  = "No Certificate Involved";       
       String admin = "Administrator not known";
       
       if(username != null)
         user = username;
       
       if (certificate != null)
         cert = certificate.getSerialNumber().toString(16) + ", issuer: " + certificate.getIssuerDN().toString();
       
       if(admininfo.getAdminType() == Admin.TYPE_CLIENTCERT_USER)
          admin = Admin.ADMINTYPETEXTS[Admin.TYPE_CLIENTCERT_USER] + ", Certificate SNR : " + admininfo.getAdminData();
       else
         if(admininfo.getAdminType() == Admin.TYPE_PUBLIC_WEB_USER){
            if(admininfo.getAdminData() != null){
              if(!admininfo.getAdminData().equals(""))  
                admin = Admin.ADMINTYPETEXTS[Admin.TYPE_PUBLIC_WEB_USER]  + ", IP Address : " + admininfo.getAdminData();              
            }    
            else
              admin = Admin.ADMINTYPETEXTS[Admin.TYPE_PUBLIC_WEB_USER];                
         }else
            admin = Admin.ADMINTYPETEXTS[admininfo.getAdminType()]; 
               
       if(event < LogEntry.EVENT_ERROR_BOUNDRARY){
         // Do Log4j Informational logging.             
         log.info(DateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.LONG).format(time) + ", CAId : " + caid + ", " + LogEntry.MODULETEXTS[module] +  ", " + LogEntry.EVENTNAMES_INFO[event] + ", Administrator : " + 
                  admin + ", User : " + user + ", Certificate : " + cert + ", Comment : " + comment);  
       }
       else{
         // Do Log4j error logging.   
         log.error(DateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.LONG).format(time) + ", CAId : " + caid + ", " + LogEntry.MODULETEXTS[module] + ", " + LogEntry.EVENTNAMES_ERROR[event - LogEntry.EVENT_ERROR_BOUNDRARY] + ", Administrator : " + 
                   admin + ", User : " + user + ", Certificate : " + cert + ", Comment : " + comment);  
       }    
    }
    
     /**
     * @see se.anatom.ejbca.log.ILogDevice
     */
    public void log(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception){
        log(admininfo, caid, module, time, username, certificate, event, comment);
        log.error("Exception : ",exception); 
    }
}
