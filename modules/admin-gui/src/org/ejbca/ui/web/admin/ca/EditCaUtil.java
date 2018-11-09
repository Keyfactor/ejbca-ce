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
package org.ejbca.ui.web.admin.ca;

import org.apache.commons.lang.StringUtils;

/**
 * 
 * @version $Id$
 *
 */
public final class EditCaUtil {
    
    public static final String MANAGE_CA_NAV = "managecas";
    public static final String EDIT_CA_NAV = "editcapage";
    public static final String SIGN_CERT_REQ_NAV = "recievefile";
    public static final String DISPLAY_RESULT_NAV = "displayresult";
    public static final int CERTREQGENMODE = 0;
    public static final int CERTGENMODE = 1;
    public static final String DEFAULT_KEY_SIZE = "2048";
    public static final String LINK_CERT_BASE_URI = "cacertreq?cmd=linkcert&";
    
    public static String getTrimmedName(final String name) {
        if (name != null && !name.isEmpty()) {
            return name.replaceAll("\\([^()]*\\)", StringUtils.EMPTY).replaceAll(", ", StringUtils.EMPTY);
        } else {
            return StringUtils.EMPTY;
        }
    }
}
