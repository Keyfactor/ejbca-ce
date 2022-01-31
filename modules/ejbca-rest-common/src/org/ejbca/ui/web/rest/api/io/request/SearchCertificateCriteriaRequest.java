/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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