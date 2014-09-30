/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.services;

import java.util.Properties;

/**
 * Help base class that manages that implements the init method of the interface
 * and manages the properties.
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id$
 */
public abstract class BaseAction implements IAction {

	protected Properties properties = null;
	protected String serviceName = null;
	
	/**
	 * @see org.ejbca.core.model.services.IAction#init(Properties)
	 */
	public void init(Properties properties, String serviceName) {
       this.properties = properties;
       this.serviceName = serviceName;
	}
	




}
