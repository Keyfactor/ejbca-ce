package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;
import java.math.BigInteger;

/**
 * For docs, see HardTokenIssuerDataBean
 *
 * @version $Id: HardTokenIssuerDataLocalHome.java,v 1.2 2003-02-09 14:56:16 anatom Exp $
 **/
public interface HardTokenIssuerDataLocalHome extends javax.ejb.EJBLocalHome {

    public HardTokenIssuerDataLocal create(Integer id, String alias, BigInteger certificatesn, String certissuerdn,  HardTokenIssuer issuerdata)
        throws CreateException;

    public HardTokenIssuerDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    public HardTokenIssuerDataLocal findByAlias(String alias)
        throws FinderException;
    
    public HardTokenIssuerDataLocal findByCertificateSN(String certificatesn, String certissuerdn)
        throws FinderException;    

    public Collection findAll()
        throws FinderException;
}

