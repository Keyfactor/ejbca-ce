package se.anatom.ejbca.ca.publisher;


/**
 * For docs, see PublisherDataBean
 *
 * @version $Id: PublisherDataLocal.java,v 1.1 2004-03-07 12:08:50 herrvendil Exp $
 **/

public interface PublisherDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public int getUpdateCounter();

    public void setName(String name);
    
	public String getName();
     
    public BasePublisher getPublisher();

    public void setPublisher(BasePublisher publisher);
}

