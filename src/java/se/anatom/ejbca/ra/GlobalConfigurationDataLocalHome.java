package se.anatom.ejbca.ra;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.security.cert.X509CRL;
import se.anatom.ejbca.ra.GlobalConfiguration;

/**

 * For docs, see GlobalWebConfigurationBean

 **/

public interface GlobalConfigurationDataLocalHome extends javax.ejb.EJBLocalHome {

    public GlobalConfigurationDataLocal create(String id, GlobalConfiguration globalconfiguration)
        throws CreateException;


    public GlobalConfigurationDataLocal findByPrimaryKey(String id)
        throws FinderException;


    public GlobalConfigurationDataLocal findByConfigurationId(String id)
        throws FinderException;

}

