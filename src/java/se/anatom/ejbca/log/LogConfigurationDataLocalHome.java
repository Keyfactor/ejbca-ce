package se.anatom.ejbca.log;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see LogConfigurationDataBean
 **/

public interface LogConfigurationDataLocalHome extends javax.ejb.EJBLocalHome {

    public LogConfigurationDataLocal create(Integer id, LogConfiguration logconfiguration)
        throws CreateException;


    public LogConfigurationDataLocal findByPrimaryKey(Integer id)
        throws FinderException;


}

