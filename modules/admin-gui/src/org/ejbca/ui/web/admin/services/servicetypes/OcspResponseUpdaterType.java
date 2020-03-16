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

import org.ejbca.core.model.services.OcspResponseUpdaterWorker;

/**
 * 
 * @version $Id$
 *
 */
public class OcspResponseUpdaterType extends BaseWorkerType {

    public static final String NAME = "OCSPQUEUEWORKER";

    private static final long serialVersionUID = 1L;
    
    public OcspResponseUpdaterType() {
        super(ServiceTypeUtil.OCSPRESPONSEUPDATEWORKER_SUB_PAGE, NAME, true, OcspResponseUpdaterWorker.class.getName());
        // No action available for this worker
        addCompatibleActionTypeName(NoActionType.NAME);     
        // Only periodical interval available for this worker
        addCompatibleIntervalTypeName(PeriodicalIntervalType.NAME);
    }


    
    
}
