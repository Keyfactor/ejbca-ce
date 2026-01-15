/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.proxyca;

import java.io.Serializable;
import java.util.Map;

public interface KeyFactorCommandSession {

    record Response(int httpStatus, String body) implements Serializable {
        static final long serialVersionUID = 1L;
    }

    void invalidateToken(final Integer caId);
    Response send(final Integer caId, final String method, final String path, final Map<String, String> headers, final String requestBody) throws Exception;

}
