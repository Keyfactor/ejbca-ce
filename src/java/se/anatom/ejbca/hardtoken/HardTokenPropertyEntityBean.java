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

import javax.ejb.CreateException;

import se.anatom.ejbca.BasePropertyEntityBean;
import se.anatom.ejbca.PropertyEntityPK;



/**
 * HardTokenPropertyEntityBean is a complientary class used to assign extended
 * properties like copyof to a hard token.
 *
 * Id is represented by primary key of hard token table.
 *
 *
 * @ejb.bean
 *	 xxxgenerate="false"
 *   description="This enterprise bean entity represents a hard token to certificate mappings"
 *   display-name="HardTokenPropertyDataEB"
 *   name="HardTokenPropertyData"
 *   jndi-name="HardTokenPropertyData"
 *   local-jndi-name="HardTokenPropertyData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="false"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="HardTokenPropertyEntityBean"
 *
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.pk
 *   class="se.anatom.ejbca.PropertyEntityPK"
 *   extends="java.lang.Object"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.BasePropertyDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.BasePropertyDataLocal"
 *
 * @ejb.finder
 *   description="findByProperty"
 *   signature="se.anatom.ejbca.BasePropertyDataLocal findByProperty(java.lang.String id, java.lang.String property)"
 *   query="SELECT DISTINCT OBJECT(a) from HardTokenPropertyEntityBean a WHERE a.id =?1 AND a.property=?2"
 *
 * @ejb.finder
 *   description="findIdsByPropertyAndValue"
 *   signature="Collection findIdsByPropertyAndValue(java.lang.String property, java.lang.String value)"
 *   query="SELECT DISTINCT OBJECT(a) from HardTokenPropertyEntityBean a WHERE a.property =?1 AND a.value=?2"
 */
public abstract class HardTokenPropertyEntityBean extends BasePropertyEntityBean {

  public static final String PROPERTY_COPYOF = "copyof=";

    /**
     * @ejb.persistence
     * @ejb.pk-field
     * @ejb.interface-method view-type="local"
     */
    public abstract String getId();

    /**
     * @ejb.persistence
     */
    public abstract void setId(String id);

    /**
     * @ejb.persistence
     * @ejb.pk-field
     * @ejb.interface-method view-type="local"
     */
    public abstract String getProperty();

    /**
     * @ejb.persistence
     */
    public abstract void setProperty(String property);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract String getValue();

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setValue(String value);

    /**
     * @ejb.create-method view-type="local"
     */
    public PropertyEntityPK ejbCreate(String id, String property, String value) throws CreateException {
        return super.ejbCreate(id, property, value);
    }
}
