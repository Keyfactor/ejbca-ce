/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.validator;

import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;

/**
 * A test class for annotation @ValidSearchCertificateCriteriaRestRequest.
 *
 * @version $Id: ValidSearchCertificateCriteriaRestRequestTestClass.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class ValidSearchCertificateCriteriaRestRequestTestClass {

    @ValidSearchCertificateCriteriaRestRequest
    private SearchCertificateCriteriaRestRequest criteria;

    ValidSearchCertificateCriteriaRestRequestTestClass(final SearchCertificateCriteriaRestRequest criteria) {
        this.criteria = criteria;
    }
}
