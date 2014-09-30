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
package org.ejbca.core.model.services.actions;

import java.util.Map;

import org.apache.log4j.Logger;
import org.ejbca.core.model.services.ActionException;
import org.ejbca.core.model.services.ActionInfo;
import org.ejbca.core.model.services.BaseAction;

/**
 * Dummy Action used for demonstration purposes and some testing
 * 
 * Shows which methods that are necessary to implement a action
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id$
 */
public class DummyAction extends BaseAction {
	
	private static final Logger log = Logger.getLogger(DummyAction.class);

	/**
	 * @see org.ejbca.core.model.services.IAction#performAction(org.ejbca.core.model.services.ActionInfo)
	 */
	public void performAction(ActionInfo actionInfo, Map<Class<?>, Object> ejbs) throws ActionException {
		log.trace(">DummyAction.performAction");
		this.properties.get("somedata");
		// Do nothing
	}

}
