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
package org.ejbca.ui.web.admin.attribute;

/**
 * Constant class containing mappings for request and session attributes.
 *
 * @version $Id$
 */
public final class AttributeMapping {

    public static final class REQUEST {

        public static final String AUTHENTICATION_TOKEN = "authenticationtoken";

    }

    public static final class SESSION {

        public static final String CA_INTERFACE_BEAN = "cabean";

        public static final String EJBCA_WEB_BEAN = "ejbcawebbean";

        public static final String RA_INTERFACE_BEAN = "rabean";

    }
}
