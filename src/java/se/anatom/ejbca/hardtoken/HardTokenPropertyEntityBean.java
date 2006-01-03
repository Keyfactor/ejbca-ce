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

package se.anatom.ejbca.hardtoken;

import se.anatom.ejbca.BaseEntityBean;

import javax.ejb.CreateException;


/**
 * HardTokenPropertyEntityBean is a complientary class used to assign extended
 * properties like copyof to a hard token.
 *
 * Id is represented by primary key of hard token table.
 *
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a hard token to certificate mappings"
 *   display-name="HardTokenPropertyDataEB"
 *   name="HardTokenPropertyData"
 *   jndi-name="HardTokenPropertyData"
 *   local-jndi-name="HardTokenPropertyData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="HardTokenPropertyDataBean"
 *
 * @ejb.pk
 *   class="se.anatom.ejbca.hardtoken.HardTokenPropertyPK"
 *   extends="java.lang.Object"
 *
 * @ejb.persistence table-name = "HardTokenPropertyData"
 * 
 * @ejb.home
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.hardtoken.HardTokenPropertyLocalHome"
 *
 * @ejb.interface
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.hardtoken.HardTokenPropertyLocal"
 *
 * @ejb.finder
 *   description="findByProperty"
 *   signature="se.anatom.ejbca.hardtoken.HardTokenPropertyLocal findByProperty(java.lang.String id, java.lang.String property)"
 *   query="SELECT OBJECT(a) from HardTokenPropertyDataBean a WHERE a.id =?1 AND a.property=?2"
 *
 * @ejb.finder
 *   description="findIdsByPropertyAndValue"
 *   signature="Collection findIdsByPropertyAndValue(java.lang.String property, java.lang.String value)"
 *   query="SELECT OBJECT(a) from HardTokenPropertyDataBean a WHERE a.property =?1 AND a.value=?2"
 *
 * @ejb.transaction
 *   type="Supports"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 *
 */
public abstract class HardTokenPropertyEntityBean extends BaseEntityBean {

  public static final String PROPERTY_COPYOF = "copyof=";


    /**
     * @ejb.persistence
     * @ejb.pk-field
     * @ejb.interface-method
     */
	public abstract String getId();

    /**
     * @ejb.persistence
     */
	public abstract void setId(String id);

    /**
     * @ejb.persistence
     * @ejb.pk-field
     * @ejb.interface-method
     */
	public abstract String getProperty();

    /**
     * @ejb.persistence
     */
	public abstract void setProperty(String property);

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
	public abstract String getValue();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
	public abstract void setValue(String value);

	/**
	 * Entity Bean holding data of a raadmin profile.
     * @ejb.create-method
     */
	public HardTokenPropertyPK ejbCreate(String id, String property, String value)
	       throws CreateException {
		setId(id);
		setProperty(property);
		setValue(value);
        return null;
	}

	public void ejbPostCreate(String id, String property, String value) {
		// Do nothing. Required.
	}
}
