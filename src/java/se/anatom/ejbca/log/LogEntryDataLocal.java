package se.anatom.ejbca.log;

import java.util.Date;

/**
 * For docs, see LogEntryDataBean
 *
 * @version $Id: LogEntryDataLocal.java,v 1.3 2003-01-12 17:16:31 anatom Exp $
 **/
public interface LogEntryDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public int getAdminType();
    
    public String getAdminData();
    
    public int getModule();
    
    public String getUsername();

    public String getCertificateSNR();
  
    public int getEvent();
       
    public String getComment();
      
    public Date getTimeAsDate();

}

