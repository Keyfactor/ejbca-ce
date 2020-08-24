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

package org.ejbca.ui.web.admin;

import java.io.Serializable;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;

import org.cesecore.authorization.control.StandardRules;

@ManagedBean
@SessionScoped
public class InitExistingPkiMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    
    public InitExistingPkiMBean() {
        super(StandardRules.ROLE_ROOT.resource());
    }

    public String acttionNext() {
        return "next";
    }
    
    public String actionBack() {
        return "back";
    }
}
