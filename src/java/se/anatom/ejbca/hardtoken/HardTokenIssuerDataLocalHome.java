package se.anatom.ejbca.hardtoken;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see HardTokenIssuerDataBean
 *
 * @version $Id: HardTokenIssuerDataLocalHome.java,v 1.6 2004-01-08 14:31:26 herrvendil Exp $
 **/
public interface HardTokenIssuerDataLocalHome extends javax.ejb.EJBLocalHome {

    public HardTokenIssuerDataLocal create(Integer id, String alias, int admingroupid,  HardTokenIssuer issuerdata)
        throws CreateException;

    public HardTokenIssuerDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    public HardTokenIssuerDataLocal findByAlias(String alias)
        throws FinderException;
       

    public Collection findAll()
        throws FinderException;
}

