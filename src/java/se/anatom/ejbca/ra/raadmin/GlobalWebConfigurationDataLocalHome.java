package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.security.cert.X509CRL;
import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;

/**

 * For docs, see GlobalWebConfigurationBean

 **/

public interface GlobalWebConfigurationDataLocalHome extends javax.ejb.EJBLocalHome {

    public GlobalWebConfigurationDataLocal create(String id, GlobalConfiguration globalconfiguration)
        throws CreateException;


    public GlobalWebConfigurationDataLocal findByPrimaryKey(String id)
        throws FinderException;


    public GlobalWebConfigurationDataLocal findByConfigurationId(String id)
        throws FinderException;

}

