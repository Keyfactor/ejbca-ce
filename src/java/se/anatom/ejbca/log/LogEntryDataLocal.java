package se.anatom.ejbca.log;
import java.rmi.RemoteException;

import java.util.Date;

/**
 * For docs, see LogEntryDataBean
 *
 * @version $Id: LogEntryDataLocal.java,v 1.2 2002-09-17 09:19:46 herrvendil Exp $
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

