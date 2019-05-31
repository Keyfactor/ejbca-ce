/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
