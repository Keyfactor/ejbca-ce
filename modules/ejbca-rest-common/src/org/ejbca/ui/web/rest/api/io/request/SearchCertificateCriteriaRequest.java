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
package org.ejbca.ui.web.rest.api.io.request;

import java.util.List;

/**
 * Type for REST requests including certificate search criteria.
 */
public interface SearchCertificateCriteriaRequest {

    /**
     * Return the list of search criteria.
     * 
     * @return the list of search criteria or an empty list.
     */
    List<SearchCertificateCriteriaRestRequest> getCriteria();

}