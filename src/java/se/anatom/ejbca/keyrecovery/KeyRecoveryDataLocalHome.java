package se.anatom.ejbca.keyrecovery;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;
import java.math.BigInteger;
import java.security.KeyPair;

/**
 * For docs, see KeyRecoveryDataBean
 *
 * @version $Id: KeyRecoveryDataLocalHome.java,v 1.1 2003-02-12 13:21:30 herrvendil Exp $
 **/

public interface KeyRecoveryDataLocalHome extends javax.ejb.EJBLocalHome {

    public KeyRecoveryDataLocal create(BigInteger certificatesn, String issuerdn, String username, KeyPair keypair)
        throws CreateException;

    public KeyRecoveryDataLocal findByPrimaryKey(KeyRecoveryDataPK pk)
        throws FinderException;
    
    public Collection findByUsername(String username)
        throws FinderException;  
    
    public Collection findByUserMark(String username)
        throws FinderException;      

}

