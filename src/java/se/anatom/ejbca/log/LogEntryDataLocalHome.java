package se.anatom.ejbca.log;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Date;

/**
 * For docs, see LogEntryDataBean
 *
 * @version $Id: LogEntryDataLocalHome.java,v 1.1 2002-09-12 17:12:14 herrvendil Exp $
 **/

public interface LogEntryDataLocalHome extends javax.ejb.EJBLocalHome {

    public LogEntryDataLocal create(Integer id, int admintype, String admindata, Date time, String username, String certificatesnr, int event, String comment)
        throws CreateException;

    public LogEntryDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

}

