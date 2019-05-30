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

import java.util.Collections;

/**
 *
 * @version $Id: SearchCertificatesRestRequestBuilder.java 29544 2018-08-01 12:07:08Z mikekushner $
 */
public class SearchCertificatesRestRequestBuilder extends SearchCertificatesRestRequest {

    public static org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestBuilder.SearchCertificatesRestRequestBuilder withDefaults() {
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.QUERY.name())
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .value("TEST")
                .build();
        return org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestBuilder
                .builder()
                .maxNumberOfResults(1)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest));
    }

}
