package se.anatom.ejbca;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;




/**
 * For docs, see BasePropertyDataBean
 *
 * @version $Id: BasePropertyDataLocalHome.java,v 1.2 2004-01-25 09:37:10 herrvendil Exp $
 */
public interface BasePropertyDataLocalHome extends javax.ejb.EJBLocalHome {

    public BasePropertyDataLocal create(String id, String property,
                                        String value) throws CreateException;


    public BasePropertyDataLocal findByPrimaryKey(PropertyEntityPK pk)
        throws FinderException;

    /**
     * Method used to find a entity given the id and property. From this entity
     * can the value be extracted.
     * 
     *
     * @throws FinderException if nothing matching could be found.
     */
    public BasePropertyDataLocal findByProperty(String id, String property)
        throws FinderException;
        
            
	/**
	 * findIdsByPropertyAndValue
	 * 
	 * Used to find all id's having matching property and values
	 
	 *
	 * @return A Collection local iterfaces of matching entities.
	 *
	 * @throws FinderException if nothing matching could be found.
	 */
	public Collection findIdsByPropertyAndValue(String property, String value)
		throws FinderException;


}
