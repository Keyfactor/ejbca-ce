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

import org.ejbca.core.model.services.workers.HsmKeepAliveWorker;

/**
 * This worker type exists with the express purpose of keeping a session to an HSM slot from timing out. It replaces
 * the previous need of creating crontab calls to the healthchecker. 
 * 
 * @version $Id$
 *
 */
public class HsmKeepAliveWorkerType extends BaseWorkerType {

    public static final String NAME = "HSMKEEPALIVEWORKER";
    
    private static final long serialVersionUID = -1598910154971679252L;
    
    public HsmKeepAliveWorkerType() {
        super("hsmkeepaliveworker.jsp", NAME, true, HsmKeepAliveWorker.class.getName());
        // No action available for this worker
        deleteAllCompatibleActionTypes();
        addCompatibleActionTypeName(NoActionType.NAME);
        //deleteAllCompatibleIntervalTypes();
        addCompatibleIntervalTypeName(PeriodicalIntervalType.NAME);
        
    }
    


}
