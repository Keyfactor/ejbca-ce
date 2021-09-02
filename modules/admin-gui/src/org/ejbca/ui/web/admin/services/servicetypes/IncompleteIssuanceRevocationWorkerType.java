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

import org.ejbca.core.model.services.workers.IncompleteIssuanceRevocationWorker;

/**
 *
 */
public class IncompleteIssuanceRevocationWorkerType extends BaseWorkerType {

    public static final String NAME = "INCOMPLETEISSUANCEREVOCATIONWORKER";
    
    private static final long serialVersionUID = 1;
    
    public IncompleteIssuanceRevocationWorkerType() {
        super(ServiceTypeUtil.HSMKEEPALIVEWORKER_SUB_PAGE, NAME, true, IncompleteIssuanceRevocationWorker.class.getName());
        // No action available for this worker
        deleteAllCompatibleActionTypes();
        addCompatibleActionTypeName(NoActionType.NAME);
        addCompatibleIntervalTypeName(PeriodicalIntervalType.NAME);
        
    }
    


}
