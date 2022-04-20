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
package org.ejbca.ui.web.rest.api.builder;

import java.util.Collections;

import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;

/**
 *
 * @version $Id: SearchCertificatesRestRequestBuilder.java 29544 2018-08-01 12:07:08Z mikekushner $
 */
public class SearchCertificatesRestRequestTestBuilder extends SearchCertificatesRestRequest {

    public static SearchCertificatesRestRequestBuilder withDefaults() {
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.QUERY.name())
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .value("TEST")
                .build();
        return SearchCertificatesRestRequestTestBuilder
                .builder()
                .maxNumberOfResults(1)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest));
    }

}
