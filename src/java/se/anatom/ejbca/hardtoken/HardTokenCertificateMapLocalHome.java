package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;


/**
 * For docs, see HardTokenCertificateMapBean
 *
 * @version $Id: HardTokenCertificateMapLocalHome.java,v 1.4 2003-09-03 20:05:28 herrvendil Exp $
 **/

public interface HardTokenCertificateMapLocalHome extends javax.ejb.EJBLocalHome {

    public HardTokenCertificateMapLocal create(String certificatefingerprint, String tokensn)
        throws CreateException;

    public HardTokenCertificateMapLocal findByPrimaryKey(String certificatefingerprint)
        throws FinderException;
    
    public Collection findByTokenSN(String tokensn)
        throws FinderException;    

    public Collection findAll()
        throws FinderException;
}

