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

    
    public static Object getTrimmedName(final String name) {
        if (name != null && !name.isEmpty()) {
            return name.replaceAll("\\([^()]*\\)", StringUtils.EMPTY).replaceAll(", ", StringUtils.EMPTY);
        } else {
            return StringUtils.EMPTY;
        }
    }
}
