package se.anatom.ejbca;

import javax.ejb.CreateException;



/**
 * Base class for property entity beans implementing required methods and helpers.
 * A property entity bean extends other entity beans with propertys.
 * 
 * Primary Key is a combined id and property hash.
 * id (Integer) primary key of entity bean using this property entity bean.
 * property String should be one of the property constants.
 * value (String) the value of the property.
 *
 * @version $Id: BasePropertyEntityBean.java,v 1.0 2003/12/26 12:37:16 herrvendil Exp 
 */
public abstract class BasePropertyEntityBean extends BaseEntityBean {

	public abstract PropertyEntityPK getPK();
	public abstract void setPK(PropertyEntityPK pk);


	public abstract int getId();
	public abstract void setId(int id);


	public abstract String getProperty();
	public abstract void setProperty(String property);


	public abstract String getValue();
	public abstract void setValue(String value);

    /**
     * Creates a new BasePropertyEntityBean object.
     */
    public BasePropertyEntityBean() {
        super();
    }
    
	/**
	 * Entity Bean holding data of a raadmin profile.
	 *
	 * @param certificateprofilename DOCUMENT ME!
	 * @param certificateprofilename
	 * @param certificateprofile is the CertificateProfile.
	 *
	 * @return null
	 */
	public PropertyEntityPK ejbCreate(int id, String property, String value)
	       throws CreateException {
	       	
	    PropertyEntityPK pk = new PropertyEntityPK(id,property); 
	    setPK(pk);   	
		setId(id);
		setProperty(property);
		setValue(value);
		
		return pk;
	}

	
	public void ejbPostCreate(int id, String property, String value) {
		// Do nothing. Required.
	}    
    

}
