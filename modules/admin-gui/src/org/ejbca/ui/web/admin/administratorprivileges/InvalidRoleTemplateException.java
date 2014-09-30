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
package org.ejbca.ui.web.admin.administratorprivileges;

/**
 * This exception is thrown when an invalid role template is used to
 * add access rules to a role. 
 * 
 * @version $Id$
 *
 */
public class InvalidRoleTemplateException extends Exception {

    private static final long serialVersionUID = 4861727751816843229L;

    public InvalidRoleTemplateException() {
        super();
    }

    public InvalidRoleTemplateException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    public InvalidRoleTemplateException(String arg0) {
        super(arg0);
    }

    public InvalidRoleTemplateException(Throwable arg0) {
        super(arg0);
    }

}
