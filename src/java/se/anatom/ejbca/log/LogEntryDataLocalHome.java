package se.anatom.ejbca.log;

import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see LogEntryDataBean
 *
 * @version $Id: LogEntryDataLocalHome.java,v 1.4 2003-09-04 08:05:04 herrvendil Exp $
 **/

public interface LogEntryDataLocalHome extends javax.ejb.EJBLocalHome {

    public LogEntryDataLocal create(Integer id, int admintype, String admindata, int caid, int module, Date time, String username, String certificatesnr, int event, String comment)
        throws CreateException;

    public LogEntryDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

}

