package se.anatom.ejbca.ca.caadmin;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;



/**
 * For docs, see CADataBean
 *
 * @version $Id: CADataLocalHome.java,v 1.1 2003-09-03 16:21:29 herrvendil Exp $
 **/

public interface CADataLocalHome extends javax.ejb.EJBLocalHome {

    public CADataLocal create(String subjectdn, String name, int status, CA ca)
        throws CreateException;

    public CADataLocal findByPrimaryKey(Integer caid)
        throws FinderException;

    public CADataLocal findByName(String name)
        throws FinderException;

    public Collection findAll()
        throws FinderException;
}

