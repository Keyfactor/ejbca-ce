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

package org.cesecore.certificates.ocsp.extension;

/**
 * Context in which the {@link OCSPExtension} may be used
 * 
 * @version $Id$
 */
public enum OCSPExtensionType {

    /**
     * A Request Extension may be added to the TBSRequest.
     */
    REQUEST,

    /**
     * A SingleRequest Extension may be added to a Request in the TBSRequest.requestList.
     */
    SINGLE_REQUEST,

    /**
     * A Response Extension may be added to the ResponseData.
     */
    RESPONSE,

    /**
     * A SingleResponse Extension may be added to a SingleResponse in the ResponseData.responses.
     */
    SINGLE_RESPONSE
}
