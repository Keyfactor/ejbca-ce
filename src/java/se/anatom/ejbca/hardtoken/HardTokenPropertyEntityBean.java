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

import se.anatom.ejbca.BasePropertyEntityBean;



/**
 * HardTokenPropertyEntityBean is a complientary class used to assign extended
 * properties like copyof to a hard token.
 * 
 * Id is represented by primary key of hard token table.
 *
 * @version $Id: HardTokenPropertyEntityBean.java,v 1.0 2003/12/12 21:37:16 herrvendil Exp 
 */
public abstract class HardTokenPropertyEntityBean extends BasePropertyEntityBean {

  public static final String PROPERTY_COPYOF = "copyof=";
    
}
