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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import jakarta.ejb.EJBException;
import jakarta.el.ELException;
import jakarta.faces.FacesException;
import jakarta.faces.application.ViewExpiredException;
import jakarta.faces.context.ExceptionHandler;
import jakarta.faces.context.ExceptionHandlerFactory;
import jakarta.faces.context.ExceptionHandlerWrapper;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import jakarta.faces.event.ExceptionQueuedEvent;

import org.apache.log4j.Logger;

/**
 * Custom ExceptionHandlerFactory to be able to process and present Exceptions in an orderly fashion.
 * 
 * Enabled in faces-config.xml with
 *     &lt;factory&gt;
 *         &lt;exception-handler-factory>org.ejbca.ra.jsfext.RaExceptionHandlerFactory&lt;/exception-handler-factory&gt;
 *     &lt;/factory&gt;
 *     
 * @version $Id$
 */
public class RaExceptionHandlerFactory extends ExceptionHandlerFactory {

    private static final Logger log = Logger.getLogger(RaExceptionHandler.class);
    public static final String REQUESTMAP_KEY = "org.ejbca.ra.jsfext.throwables";
    private static final String ERROR_PAGE = "/error.xhtml";

    private final ExceptionHandlerFactory parentExceptionHandlerFactory;

    public RaExceptionHandlerFactory(ExceptionHandlerFactory parent) {
        while (parent instanceof RaExceptionHandlerFactory) {
            log.warn("Attempted to wrap a RaExceptionHandlerFactory in a RaExceptionHandlerFactory");
            if (parent == this) {
                throw new IllegalStateException("Circular reference in exception handler");
            }
            parent = parent.getWrapped();
        }
        this.parentExceptionHandlerFactory = parent;
    }

    @Override
    public ExceptionHandler getExceptionHandler() {
        return new RaExceptionHandler(parentExceptionHandlerFactory.getExceptionHandler());
    }

    /** Our custom ExceptionHandler implementation. */
    private class RaExceptionHandler extends ExceptionHandlerWrapper {
        private final ExceptionHandler wrappedExceptionHandler;

        RaExceptionHandler(final ExceptionHandler wrappedExceptionHandler) {
            this.wrappedExceptionHandler = wrappedExceptionHandler;
        }

        @Override
        public ExceptionHandler getWrapped() { return wrappedExceptionHandler; }

        @SuppressWarnings("unchecked")
        @Override
        public void handle() throws FacesException {
            final List<Throwable> throwables = new ArrayList<>();
            for (final Iterator<ExceptionQueuedEvent> iterator = super.getUnhandledExceptionQueuedEvents().iterator(); iterator.hasNext();) {
                Throwable throwable = iterator.next().getContext().getException();
                // Filter away JEE Exception wrappers
                while ((throwable instanceof FacesException || throwable instanceof EJBException || throwable instanceof ELException) && throwable.getCause() != null) {
                    throwable = throwable.getCause();
                }
                if (log.isDebugEnabled()) {
                    log.debug("Adding throwable " + throwable.getClass().getSimpleName() + ": " + throwable.getMessage());
                }
                throwables.add(throwable);
                iterator.remove();
            }
            if (!throwables.isEmpty()) {
                final FacesContext facesContext = FacesContext.getCurrentInstance();
                final ExternalContext externalContext = facesContext.getExternalContext();
                if (externalContext.getRequestMap().get(REQUESTMAP_KEY)==null) {
                    externalContext.getRequestMap().put(REQUESTMAP_KEY, throwables);
                    try {
                        externalContext.dispatch(ERROR_PAGE);
                    } catch (final IOException e) {
                        log.error("Unable to dispatch client to unknown error page '" + ERROR_PAGE + "'.", e);
                    }
                    facesContext.responseComplete();
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Additional ExceptionHandler invocation during same round trip...");
                    }
                    boolean hasViewExpiredException = false;
                    for (final Throwable throwable : throwables) {
                        if (throwable instanceof ViewExpiredException) {
                            hasViewExpiredException = true;
                            break;
                        }
                    }
                    for (final Throwable throwable : (List<Throwable>) externalContext.getRequestMap().get(REQUESTMAP_KEY)) {
                        if (hasViewExpiredException && throwable instanceof ViewExpiredException) {
                            if (log.isDebugEnabled()) {
                                log.debug("Skipping add of another ViewExpiredException.");
                            }
                        } else {
                            throwables.add(throwable);
                        }
                    }
                    externalContext.getRequestMap().put(REQUESTMAP_KEY, throwables);
                }
            }
            getWrapped().handle();
        }
    }
}
