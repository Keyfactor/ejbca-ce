/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.endentity;

/**
 * Interface common for all approval requests regarding end entities.
 * 
 * @version $Id$
 *
 */
public interface EndEntityApprovalRequest {

    /**
     * @return the end entity information member for this approval request. In the case of an edit request, will return the new value. 
     */
    EndEntityInformation getEndEntityInformation();
}
