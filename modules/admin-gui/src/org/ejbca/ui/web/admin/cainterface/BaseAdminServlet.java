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
package org.ejbca.ui.web.admin.cainterface;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

import org.cesecore.authentication.tokens.AuthenticationToken;

import com.keyfactor.util.CryptoProviderTools;

import static org.ejbca.ui.web.admin.attribute.AttributeMapping.REQUEST;

/**
 * Base servlet class for all AdminWeb pages.
 *
 * @version $Id$
 */
public abstract class BaseAdminServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            CryptoProviderTools.installBCProvider(); // Install BouncyCastle provider
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }

    /**
     * Returns the AuthenticationToken from the request attribute or throws a ServletException in case of missing one.
     *
     * @param httpServletRequest HttpServletRequest
     * @return AuthenticationToken
     * @throws ServletException in case of missing AuthenticationToken.
     */
    protected AuthenticationToken getAuthenticationToken(final HttpServletRequest httpServletRequest) throws ServletException {
        final Object authenticationTokenAttribute = httpServletRequest.getAttribute(REQUEST.AUTHENTICATION_TOKEN);
        if (authenticationTokenAttribute == null) {
            throw new ServletException("Cannot get AuthenticationToken");
        }
        return (AuthenticationToken) authenticationTokenAttribute;
    }
}
