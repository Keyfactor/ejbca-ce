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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.util.Collection;


/**
 * Class representing an Worker Type, should be registered in the 
 * ServiceTypesManager. Should be inhereted by all worker managed beans.
 * 
 * Defines which actions and interval that are compatible with this worker
 *
 * @author Philip Vendil 2006 sep 29
 *
 * @version $Id: WorkerType.java 5585 2008-05-01 20:55:00Z anatom $
 */
public abstract class WorkerType extends ServiceType {


	
	public WorkerType(String subViewPage, String name, boolean translatable) {
		super(subViewPage, name, translatable);
	}

	/**
	 * @return the names of the Compatible Action Types
	 */
	public abstract Collection getCompatibleActionTypeNames();

	/**
	 * @return the names of the Compatible Interval Types
	 */
	public abstract Collection getCompatibleIntervalTypeNames();

}
