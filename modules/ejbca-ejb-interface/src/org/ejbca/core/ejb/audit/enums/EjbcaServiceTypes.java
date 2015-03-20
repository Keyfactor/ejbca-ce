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
package org.ejbca.core.ejb.audit.enums;

import org.cesecore.audit.enums.ServiceType;

/**
 * EJBCA specific security audit event service type, for audit using CESecore's audit log.
 * 
 * When doing secure audit log ServiceType is used to indicate if the log  
 * was executed from the core itself or by an external application.
 * 
 * In relation to CESeCore, EJBCA acts as an "external application" in this case.
 * 
 * @see org.cesecore.audit.enums.ServiceTypes
 * @see org.ejbca.core.ejb.audit.enums.EjbcaEventTypes
 * @see org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes
 * @version $Id$
 */
public enum EjbcaServiceTypes implements ServiceType {
    /** Enterprise JavaBeans Certificate Authority extension of the CE Security Core. */
    EJBCA;
    
    @Override
    public boolean equals(ServiceType value) {
        if(value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }
}
