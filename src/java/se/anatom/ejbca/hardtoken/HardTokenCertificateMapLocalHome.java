package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;


/**
 * For docs, see HardTokenCertificateMapBean
 *
 * @version $Id: HardTokenCertificateMapLocalHome.java,v 1.2 2003-02-09 14:56:16 anatom Exp $
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

