/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;




/**
 * For docs, see BasePropertyDataBean
 *
 * @version $Id: BasePropertyDataLocalHome.java,v 1.3 2004-04-16 07:39:01 anatom Exp $
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
