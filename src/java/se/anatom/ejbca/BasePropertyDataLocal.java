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




/**
 * For docs, see BasePropertyEntityBean
 *
 * @version $Id: BasePropertyDataLocal.java,v 1.3 2004-04-16 07:39:01 anatom Exp $
 */
public interface BasePropertyDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public String getId();    
    public String getProperty();
    
    public String getValue();
    public void setValue(String value);
}
