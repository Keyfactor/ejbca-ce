package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;
import java.util.Date;

import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;

/**
 * For docs, see HardTokenDataBean
 *
 * @version $Id: HardTokenDataLocalHome.java,v 1.1 2003-02-06 15:35:46 herrvendil Exp $
 **/

public interface HardTokenDataLocalHome extends javax.ejb.EJBLocalHome {

    public HardTokenDataLocal create(String tokensn, String username, Date createtime, Date modifytime, int tokentype, HardToken tokendata)
        throws CreateException;

    public HardTokenDataLocal findByPrimaryKey(String tokensn)
        throws FinderException;
    
    public Collection findByUsername(String username)
        throws FinderException;    

    public Collection findAll()
        throws FinderException;
}

