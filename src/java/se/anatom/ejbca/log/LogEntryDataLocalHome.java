package se.anatom.ejbca.log;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Date;

/**
 * For docs, see LogEntryDataBean
 *
 * @version $Id: LogEntryDataLocalHome.java,v 1.2 2002-09-17 09:19:46 herrvendil Exp $
 **/

public interface LogEntryDataLocalHome extends javax.ejb.EJBLocalHome {

    public LogEntryDataLocal create(Integer id, int admintype, String admindata, int module, Date time, String username, String certificatesnr, int event, String comment)
        throws CreateException;

    public LogEntryDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

}

