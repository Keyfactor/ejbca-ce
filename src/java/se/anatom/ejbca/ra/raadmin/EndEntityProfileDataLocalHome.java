package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;

import se.anatom.ejbca.ra.raadmin.EndEntityProfile;

/**
 * For docs, see EndEntityProfileDataBean
 *
 * @version $Id: EndEntityProfileDataLocalHome.java,v 1.1 2002-10-24 20:09:28 herrvendil Exp $
 **/

public interface EndEntityProfileDataLocalHome extends javax.ejb.EJBLocalHome {

    public EndEntityProfileDataLocal create(Integer id, String profilename, EndEntityProfile profile)
        throws CreateException;

    public EndEntityProfileDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    public EndEntityProfileDataLocal findByProfileName(String name)
        throws FinderException;

    public Collection findAll()
        throws FinderException;
}

