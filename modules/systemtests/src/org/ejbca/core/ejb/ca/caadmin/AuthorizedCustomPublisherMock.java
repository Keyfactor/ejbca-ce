/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ca.caadmin;

import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.ExternalScriptsAllowlist;
import org.ejbca.core.model.ca.publisher.CustomPublisherAccessRulesSupport;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;

/**
 */
public class AuthorizedCustomPublisherMock extends CustomPublisherContainer implements ICustomPublisher, CustomPublisherAccessRulesSupport {

    private static final long serialVersionUID = 1L;

    public AuthorizedCustomPublisherMock() {
        super();
        setClassPath(this.getClass().getName());
    }
    
    @Override
    public void init(Properties properties) {

    }

    @Override
    public boolean isAuthorizedToPublisher(AuthenticationToken authenticationToken) {
        return true;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isCallingExternalScript() {
        return false;        
    }

    @Override
    public void setExternalScriptsAllowlist(ExternalScriptsAllowlist allowList) {
        // Method not applicable for this publisher type!        
    }

}
