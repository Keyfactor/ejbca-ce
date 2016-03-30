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
package org.ejbca.ra.jsfext;

import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.apache.log4j.Logger;
import org.ejbca.ra.RaAuthenticationBean;

/**
 * HttpSessionListener to be able to detect/log when a user has been logged out for example due to the session has expired. 
 * 
 * @version $Id$
 */
@WebListener
public class RaHttpSessionListener implements HttpSessionListener {

    private static final Logger log = Logger.getLogger(RaHttpSessionListener.class);

    @Override
    public void sessionCreated(final HttpSessionEvent httpSessionEvent) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP session from client started. jsessionid=" + httpSessionEvent.getSession().getId());
        }
    }

    @Override
    public void sessionDestroyed(final HttpSessionEvent httpSessionEvent) {
        final RaAuthenticationBean raAuthenticationBean = (RaAuthenticationBean) httpSessionEvent.getSession().getAttribute("raAuthenticationBean");
        if (raAuthenticationBean==null) {
            log.debug("Failed to clean up after client session with jsessionid=" + httpSessionEvent.getSession().getId());
        } else {
            raAuthenticationBean.onSessionDestroyed(httpSessionEvent);
        }
    }
}
