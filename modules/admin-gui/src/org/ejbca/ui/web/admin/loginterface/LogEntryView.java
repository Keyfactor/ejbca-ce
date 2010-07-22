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
 
package org.ejbca.ui.web.admin.loginterface;

import java.rmi.RemoteException;
import java.text.DateFormat;
import java.util.Date;
import java.util.HashMap;

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.ui.web.admin.rainterface.SortBy;
import org.ejbca.util.dn.DNFieldExtractor;

/**
 * A class used as a help class for displaying LogEntries.
 *
 * @author  TomSelleck
 * @version $Id$
 */
public class LogEntryView implements java.io.Serializable, Cloneable, Comparable {
    // Public constants.
    public static final int TIME              = 0;
    public static final int ADMINTYPE         = 1;
    public static final int ADMINDATA         = 2;
    public static final int ADMINCERTSERNO    = 3;
    public static final int CA                = 4;
    public static final int MODULE            = 5;
    public static final int USERNAME          = 6;
    public static final int CERTIFICATE       = 7;
    public static final int CERTIFICATESERNO  = 8;
    public static final int EVENT             = 9;
    public static final int COMMENT           = 10;
    public static final int VERIFY            = 11;
   
    public static final String TRUE = "T";
    public static final String FALSE = "F";
    
    public static final int NUMBEROF_FIELDS=12;

    
    /** Creates a new instance of UserView */
    public LogEntryView(SubjectDNProxy dnproxy) {
      logentrydata = new String[NUMBEROF_FIELDS];   
      for(int i=0; i<  NUMBEROF_FIELDS ; i++){
        logentrydata[i] = "";    
      }
      this.dnproxy = dnproxy;
    }
    
    public LogEntryView(LogEntry logentry, SubjectDNProxy dnproxy, String[] localinfoeventnames, String[] localerroreventnames,
    		String[] localsystemeventnames, String[] localmodulenames, HashMap  caidtonamemap) throws RemoteException{
      logentrydata = new String[NUMBEROF_FIELDS];
      for(int i=0; i<  NUMBEROF_FIELDS ; i++){
        logentrydata[i] = "";    
      }         
      this.dnproxy = dnproxy; 
      setValues(logentry,localinfoeventnames,localerroreventnames, localsystemeventnames, localmodulenames, caidtonamemap);
    }
    
   
    // Public methods.
    /** Method that returns the specific logentry pointed by the parameter. */
    public String getValue(int parameter){
      return logentrydata[parameter];  
    }

    /** Method that returns the specific logentry pointed by the parameter. */
    public void setValue(int parameter, String value){
      logentrydata[parameter]=value;  
    }    
    
    /** Method that returns the logentrydata as a String array */
    public String[] getValues(){
      return logentrydata;   
    }
       
    /* Sets the values according to the values in the LogEntry object.*/ 
    public void setValues(LogEntry logentry,  String[] localinfoeventnames, String[] localerroreventnames, String[] localsystemeventnames,String[] localmodulenames, HashMap caidtonamemap) throws RemoteException{
        
       logentrydata[TIME] = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(logentry.getTime());
       this.time = logentry.getTime();
      
       logentrydata[ADMINTYPE] = Integer.toString(logentry.getAdminType());
       if (logentry.getAdminType() == Admin.TYPE_CLIENTCERT_USER) {
          String dnstring = dnproxy.getSubjectDN(logentry.getAdminData());
          if (dnstring !=null) {
            DNFieldExtractor dn = new DNFieldExtractor(dnstring, DNFieldExtractor.TYPE_SUBJECTDN);           
            logentrydata[ADMINCERTSERNO] = logentry.getAdminData();
            logentrydata[ADMINDATA] = dn.getField(DNFieldExtractor.CN,0) + ", " + dn.getField(DNFieldExtractor.O,0);
          }  
       } else {
          if (logentry.getAdminType() == Admin.TYPE_PUBLIC_WEB_USER) {
            if (logentry.getAdminData() != null) {           
              logentrydata[ADMINDATA] = "IP : " + logentry.getAdminData();
            }
          } else {    
            if (logentry.getAdminData() != null) {           
              logentrydata[ADMINDATA] = logentry.getAdminData();
            }
          }  
          if(logentrydata[ADMINDATA] == null) {
        	  logentrydata[ADMINDATA] = "";
          }
       }
       
              
       logentrydata[CA]    = (String) caidtonamemap.get(new Integer(logentry.getCAId()));
       
       logentrydata[MODULE] = localmodulenames[logentry.getModule()];
         
       logentrydata[USERNAME] = logentry.getUsername();
       if (logentrydata[USERNAME] != null && logentrydata[USERNAME].trim().equals("")) {
         logentrydata[USERNAME] = null;
       }
       
       if ( (logentry.getCertificateSNR() != null) && (logentry.getCertificateSNR().trim().equals("")) ) {
            logentrydata[CERTIFICATESERNO] = null;
       } else {
    	   logentrydata[CERTIFICATESERNO] = logentry.getCertificateSNR();
       }
         
       if (logentrydata[CERTIFICATESERNO] != null) {
          String dnstring = dnproxy.getSubjectDN(logentry.getCertificateSNR()); 
          if(dnstring != null){
            DNFieldExtractor dn = new DNFieldExtractor(dnstring, DNFieldExtractor.TYPE_SUBJECTDN); 
            logentrydata[CERTIFICATE] = dn.getField(DNFieldExtractor.CN,0) + ", " + dn.getField(DNFieldExtractor.O,0);
          }  
       }
       
       if (logentry.getEvent() < LogConstants.EVENT_ERROR_BOUNDRARY) {
           logentrydata[EVENT] = localinfoeventnames[logentry.getEvent()];
       } else if (logentry.getEvent() < LogConstants.EVENT_SYSTEM_BOUNDRARY) {
           logentrydata[EVENT] = localerroreventnames[logentry.getEvent() - LogConstants.EVENT_ERROR_BOUNDRARY];         
       } else {
           logentrydata[EVENT] = localsystemeventnames[logentry.getEvent() - LogConstants.EVENT_SYSTEM_BOUNDRARY];         
       }
       
       logentrydata[COMMENT] = logentry.getComment();  
       logentrydata[VERIFY] = logentry.getVerifyResult();
    }
          
    public int compareTo(Object obj) {
      int returnvalue = -1;
      int sortby = this.sortby.getSortBy();
      switch(sortby){
          case SortBy.USERNAME : 
            returnvalue = logentrydata[USERNAME].compareTo(((LogEntryView) obj).getValue(USERNAME));
            break;  
          case SortBy.ADMINTYPE : 
            returnvalue = logentrydata[ADMINTYPE].compareTo(((LogEntryView) obj).getValue(ADMINTYPE));            
            break;  
          case SortBy.ADMINDATA : 
            returnvalue = logentrydata[ADMINDATA].compareTo(((LogEntryView) obj).getValue(ADMINDATA));            
            break;     
          case SortBy.CA : 
            returnvalue = logentrydata[CA].compareTo(((LogEntryView) obj).getValue(CA));            
            break;                
          case SortBy.MODULE :
            returnvalue = logentrydata[MODULE].compareTo(((LogEntryView) obj).getValue(MODULE));            
            break;               
          case SortBy.CERTIFICATE : 
            returnvalue = logentrydata[CERTIFICATE].compareTo(((LogEntryView) obj).getValue(CERTIFICATE));            
            break;  
          case SortBy.EVENT : 
            returnvalue = logentrydata[EVENT].compareTo(((LogEntryView) obj).getValue(EVENT));            
            break;             
          case SortBy.COMMENT : 
            returnvalue = logentrydata[COMMENT].compareTo(((LogEntryView) obj).getValue(COMMENT));            
            break;
          case SortBy.TIME :
            returnvalue = time.compareTo(((LogEntryView) obj).getTime());  
            break;
          default:
            returnvalue = time.compareTo(((LogEntryView) obj).getTime());              
      }
      if (this.sortby.getSortOrder() == SortBy.DECENDING) {
        returnvalue = 0-returnvalue;   
      }
      return returnvalue;  
    }
    
    public void setSortBy(SortBy sortby){
      this.sortby=sortby;   
    }
    
    public Date getTime(){return time;}
    
    // Private constants.  
    
    // Private methods.
    private String[] logentrydata; 
    private SortBy sortby; 
    private Date time;
    private SubjectDNProxy dnproxy;
}
