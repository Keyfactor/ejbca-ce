package se.anatom.ejbca.ca.publisher;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a publisher in the ca.
 * Information stored:
 * <pre>
 *  id (Primary key)
 *  name (of the publisher)
 *  updatecount, help counter incremented each update used to check if a publisher proxy class should update its data 
 *  publisher (Data saved concerning the publisher)
 * </pre>
 *
 * @version $Id: PublisherDataBean.java,v 1.1 2004-03-07 12:08:50 herrvendil Exp $
 **/

public abstract class PublisherDataBean extends BaseEntityBean {

    private static Logger log = Logger.getLogger(PublisherDataBean.class);
    
    private BasePublisher publisher = null;

    public abstract Integer getId();
    public abstract void setId(Integer id);

    public abstract String getName();
    public abstract void setName(String name);
    
	public abstract int getUpdateCounter();
	public abstract void setUpdateCounter(int updatecounter);
      

    public abstract String getData();
    public abstract void setData(String data);
    
    
   
    /** 
     * Method that returns the publisher data and updates it if nessesary.
     */    
    
    public BasePublisher getPublisher(){		
		        
  	  if(publisher == null){
	    java.beans.XMLDecoder decoder;
		try {
		  decoder =
			new java.beans.XMLDecoder(
					new java.io.ByteArrayInputStream(getData().getBytes("UTF8")));
		} catch (UnsupportedEncodingException e) {
		  throw new EJBException(e);
		}
		HashMap data = (HashMap) decoder.readObject();
		decoder.close();
             
		switch (((Integer) (data.get(BasePublisher.TYPE))).intValue()) {
		  case LdapPublisher.TYPE_LDAPPUBLISHER :
		    publisher = new LdapPublisher();
		    break;
		  case ActiveDirectoryPublisher.TYPE_ADPUBLISHER:
		    publisher =  new ActiveDirectoryPublisher();      
		    break;
		  case CustomPublisherContainer.TYPE_CUSTOMPUBLISHERCONTAINER:
		  	publisher =  new CustomPublisherContainer();      
		  	break;  		  		    
		}
		  
		publisher.loadData(data);		  
	  }	
		                 
		return publisher;                          
    }
    
    /** 
     * Method that saves the publisher data to database.
     */    
    public void setPublisher(BasePublisher publisher){
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
       
		java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
		encoder.writeObject(publisher.saveData());
		encoder.close();
		       
		try {
            if (log.isDebugEnabled()) {
                log.debug("Profiledata: \n" + baos.toString("UTF8"));                
            }
			setData(baos.toString("UTF8"));
		} catch (UnsupportedEncodingException e) {
          throw new EJBException(e);
		}
       
		this.publisher = publisher;    	       
        setUpdateCounter(getUpdateCounter() +1);          
    }
    

    //
    // Fields required by Container
    //
    /**
     * Passivates bean, resets CA data.
     */
    public void ejbPassivate() {
        this.publisher = null;
    }


    /**
     * Entity Bean holding data of a publisher.
     *
     * @return null
     *
     **/

    public Integer ejbCreate(Integer id, String name, BasePublisher publisher) throws CreateException {
        setId(id);
        setName(name);
        this.setUpdateCounter(0); 
        if(publisher != null)           
          setPublisher(publisher);
        
        log.debug("Created Hard Token Profile "+ name );
        return id;
    }

    public void ejbPostCreate(Integer id, String name, BasePublisher publisher) {
        // Do nothing. Required.
    }
}
