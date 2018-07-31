package org.ejbca.ui.web.rest.api.io.request;

import java.util.Collections;

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
