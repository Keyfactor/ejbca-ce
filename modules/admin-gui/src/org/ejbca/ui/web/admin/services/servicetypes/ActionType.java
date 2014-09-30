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
package org.ejbca.ui.web.admin.services.servicetypes;


/**
 * Class representing an Action Type, should be registered in the 
 * ServiceTypesManager. Should be inherited by all action managed beans.
 * 
 *
 * @version $Id$
 */
public abstract class ActionType extends ServiceType {

	private static final long serialVersionUID = -7411725269781465619L;

	public ActionType(String subViewPage, String name, boolean translatable) {
		super(subViewPage, name, translatable);
	}

}
