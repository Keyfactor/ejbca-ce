package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;

import java.util.Collection;

/**
 * For docs, see HardTokenProfileDataBean
 *
 * @version $Id: HardTokenProfileDataLocalHome.java,v 1.1 2003-12-05 14:50:26 herrvendil Exp $
 **/
public interface HardTokenProfileDataLocalHome extends javax.ejb.EJBLocalHome {

    public HardTokenProfileDataLocal create(Integer id, String name, HardTokenProfile profile)
        throws CreateException;

    public HardTokenProfileDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    public HardTokenProfileDataLocal findByName(String name)
        throws FinderException;
    

    public Collection findAll()
        throws FinderException;
}

