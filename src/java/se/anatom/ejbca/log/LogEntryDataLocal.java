package se.anatom.ejbca.log;
import java.rmi.RemoteException;

import java.util.Date;

/**
 * For docs, see LogEntryDataBean
 *
 * @version $Id: LogEntryDataLocal.java,v 1.1 2002-09-12 17:12:13 herrvendil Exp $
 **/

public interface LogEntryDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public int getAdminType();
    
    public String getAdminData();
    
    public String getUsername();

    public String getCertificateSNR();
  
    public int getEvent();
       
    public String getComment();
      
    public Date getTimeAsDate();

}

