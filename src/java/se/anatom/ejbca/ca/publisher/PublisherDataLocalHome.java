package se.anatom.ejbca.ca.publisher;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import java.util.Collection;

/**
 * For docs, see PublisherDataBean
 *
 * @version $Id: PublisherDataLocalHome.java,v 1.1 2004-03-07 12:08:50 herrvendil Exp $
 **/
public interface PublisherDataLocalHome extends javax.ejb.EJBLocalHome {

    public PublisherDataLocal create(Integer id, String name, BasePublisher publisher)
        throws CreateException;

    public PublisherDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    public PublisherDataLocal findByName(String name)
        throws FinderException;
    

    public Collection findAll()
        throws FinderException;
}

