package se.anatom.ejbca.log;

import java.util.Date;


/**
 * For docs, see LogEntryDataBean
 *
 * @version $Id: LogEntryDataLocal.java,v 1.5 2003-09-04 08:05:00 herrvendil Exp $
 **/
public interface LogEntryDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods

    public Integer getId();

    public int getAdminType();
    
    public String getAdminData();
    
    public int getCaId();
    
    public int getModule();
    
    public String getUsername();

    public String getCertificateSNR();
  
    public int getEvent();
       
    public String getComment();
      
    public Date getTimeAsDate();

}

