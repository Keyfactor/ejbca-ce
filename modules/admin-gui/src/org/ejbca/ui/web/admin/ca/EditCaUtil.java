package org.ejbca.ui.web.admin.ca;

import org.apache.commons.lang.StringUtils;

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
