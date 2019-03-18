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
package org.cesecore.keys.validation;

import java.util.Set;

/**
 * Contains methods implemented in CaaValidator that are needed from RAMasterApiSessionBean,
 * which cannot access the caa module directly (and hence the CaaValidator class)
 *
 * @version $Id$
 */
public interface CaaIdentitiesValidator {

    /**
     * @return a set of issuer names for this validator
     */
    Set<String> getIssuers();

}
