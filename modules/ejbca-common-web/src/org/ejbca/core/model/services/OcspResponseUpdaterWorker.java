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

import java.util.Map;

import org.apache.log4j.Logger;
import org.ejbca.core.model.services.ServiceExecutionResult.Result;


/**
 * 
 * @version $Id$
 *
 */
public class OcspResponseUpdaterWorker extends BaseWorker {

    private static final Logger log = Logger.getLogger(OcspResponseUpdaterWorker.class);
    
    @Override
    public ServiceExecutionResult work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        
        return new ServiceExecutionResult(Result.SUCCESS, "Service worker not yet implemented");
    }

    @Override
    public void canWorkerRun(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        // TODO Auto-generated method stub
        
    }

}
