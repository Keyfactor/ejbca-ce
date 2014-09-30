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

import org.ejbca.core.model.services.workers.CRLUpdateWorker;

/**
 * @version $Id$
 */
public class CRLUpdateWorkerType extends BaseWorkerType {
	
	private static final long serialVersionUID = 1L;
	
	public static final String NAME = "CRLUPDATEWORKER";
	
	public CRLUpdateWorkerType() {
		super("crlupdateworker.jsp", NAME, true, CRLUpdateWorker.class.getName());

		// No action available for this worker
		addCompatibleActionTypeName(NoActionType.NAME);		
		// Only periodical interval available for this worker
		addCompatibleIntervalTypeName(PeriodicalIntervalType.NAME);
	}

}
