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
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

/**
 * Use this filter to synchronize requests to your web application and
 * reduce the maximum load that each individual user can put on your
 * web application. Requests will be synchronized per session.  When more
 * than one additional requests are made while a request is in process,
 * only the most recent of the additional requests will actually be
 * processed.
 * <p>
 * If a user makes two requests, A and B, then A will be processed first
 * while B waits.  When A finishes, B will be processed.
 * <p>
 * If a user makes three or more requests (e.g. A, B, and C), then the
 * first will be processed (A), and then after it finishes the last will
 * be processed (C), and any intermediate requests will be skipped (B).
 * <p>
 * There are two additional limitations:
 * <ul>
 *   <li>Requests will be excluded from filtering if their URI matches
 *       one of the exclusion patterns.  There will be no synchronization
 *       performed if a request matches one of those patterns.</li>
 *   <li>Requests wait a maximum of 30 seconds, which can be overridden
 *       per URI pattern in the filter's configuration.</li>
 * </ul>
 * 
 * @author Kevin Chipalowsky and Ivelin Ivanov
 * Changed to WebFilter and modernized by PrimeKey
 * @version $Id$
 */
@WebFilter(filterName = "RequestControlFilter", urlPatterns = {"/*"}, initParams= {
        @WebInitParam(name="excludePattern.1",value="/img/.*"),
        @WebInitParam(name="excludePattern.2",value="/css/.*"),
        @WebInitParam(name="excludePattern.2",value="/js/.*")
})
public class RequestControlFilter implements Filter {

    private static final Logger log = Logger.getLogger(RequestControlFilter.class);

    /**
     * Initialize this filter by reading its configuration parameters
     * 
     * @param config  Configuration from web.xml file
     */
    @Override
    public void init( FilterConfig config ) throws ServletException
    {
        log.debug("RequestControlFilter: init");
        // parse all of the initialization parameters, collecting the exclude
        // patterns and the max wait parameters
        excludePatterns = new LinkedList<Pattern>();
        maxWaitDurations = new HashMap<Pattern,Long>();
        Enumeration<String> en = config.getInitParameterNames();
        while (en.hasMoreElements()) {
            String paramName = (String)en.nextElement();
            String paramValue = config.getInitParameter(paramName);
            if (paramName.startsWith("excludePattern")) {
                // compile the pattern only this once
                Pattern excludePattern = Pattern.compile( paramValue );
                if (log.isDebugEnabled()) {
                    log.debug("Adding excludePattern: "+paramValue);
                }
                excludePatterns.add(excludePattern);
            } else if (paramName.startsWith( "maxWaitMilliseconds.")) {
                // the delay gets parsed from the parameter name
                String durationString = paramName.substring("maxWaitMilliseconds.".length());
                int endDuration = durationString.indexOf('.');
                if (endDuration != -1) {
                    durationString = durationString.substring(0, endDuration);
                }
                Long duration = new Long(durationString);

                // compile the corresponding pattern, and store it with this delay in the map
                Pattern waitPattern = Pattern.compile(paramValue);
                maxWaitDurations.put(waitPattern, duration);
                if (log.isDebugEnabled()) {
                    log.debug("Adding maxWaitDurations: "+paramValue);
                }
            }
        }
    }

    /**
     * Called with the filter is no longer needed.
     */
    @Override
    public void destroy() {
        // there is nothing to do
    }

    /**
     * Synchronize the request and then either process it or skip it,
     * depending on what other requests current exist for this session.
     * See the description of this class for more details.
     */
    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain chain)
                    throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest)request;
        HttpSession session = httpRequest.getSession();

        // if this request is excluded from the filter, then just process it
        if (!isFilteredRequest( httpRequest)) {
            if (log.isTraceEnabled()) {
                log.trace("URL not mached, not filtering: " + httpRequest.getRequestURI());
            }
            chain.doFilter(request, response);
            return;
        }
        if (log.isTraceEnabled()) {
            log.trace("URL mached, will filter: " + httpRequest.getRequestURI());
        }

        synchronized(getSynchronizationObject(session)) {
            // if another request is being processed, then wait
            if (isRequestInProcess(session)) {
                // Put this request in the queue and wait
                if (log.isTraceEnabled()) {
                    log.trace("Put this request in the queue and wait: "+httpRequest);
                }
                enqueueRequest(httpRequest);
                if (!waitForRelease(httpRequest)) {
                    if (log.isTraceEnabled()) {
                        log.trace("this request was replaced in the queue by another request, so it need not be processed");
                    }
                    // this request was replaced in the queue by another request, so it need not be processed
                    return;
                }
            }

            // lock the session, so that no other requests are processed until this one finishes
            setRequestInProgress(httpRequest);
        }

        // process this request, and then release the session lock regardless of
        // any exceptions thrown farther down the chain.
        try {
            chain.doFilter(request, response);
        } finally {
            releaseQueuedRequest(httpRequest);
        }
    }

    /**
     * Get a synchronization object for this session
     * 
     * @param session
     */
    private static synchronized Object getSynchronizationObject(HttpSession session) {
        // get the object from the session.  If it does not yet exist,
        // then create one.
        Object syncObj = session.getAttribute(SYNC_OBJECT_KEY);
        if (syncObj == null) {
            syncObj = new Object();
            session.setAttribute(SYNC_OBJECT_KEY, syncObj);
        }
        return syncObj;
    }

    /**
     * Record that a request is in process so that the filter blocks additional
     * requests until this one finishes.
     * 
     * @param request
     */
    private void setRequestInProgress(HttpServletRequest request) {
        HttpSession session = request.getSession();
        session.setAttribute(REQUEST_IN_PROCESS, request);
    }

    /**
     * Release the next waiting request, because the current request
     * has just finished.
     * 
     * @param request   The request that just finished
     */
    private void releaseQueuedRequest(HttpServletRequest request) {
        HttpSession session = request.getSession();
        synchronized (getSynchronizationObject(session)) {
            // if this request is still the current one (i.e., it didn't run for too
            // long and result in another request being processed), then clear it
            // and thus release the lock
            if (session.getAttribute(REQUEST_IN_PROCESS) == request) {
                session.removeAttribute(REQUEST_IN_PROCESS);
                getSynchronizationObject(session).notify();
            }
        }
    }

    /**
     * Is this server currently processing another request for this session?
     * 
     * @param session   The request's session
     * @return          true if the server is handling another request for this session
     */
    private boolean isRequestInProcess(HttpSession session) {
        return session.getAttribute(REQUEST_IN_PROCESS) != null;
    }

    /**
     * Wait for this server to finish with its current request so that
     * it can begin processing our next request.  This method also detects if
     * its request is replaced by another request in the queue.
     *
     * @param request   Wait for this request to be ready to run
     * @return  true if this request may be processed, or false if this
     *          request was replaced by another in the queue.
     */
    private boolean waitForRelease(HttpServletRequest request) {
        HttpSession session = request.getSession();

        // wait for the currently running request to finish, or until this
        // thread has waited the maximum amount of time
        try {
            getSynchronizationObject(session).wait(getMaxWaitTime(request));
        } catch (InterruptedException ie) {
            return false;
        }

        // This request can be processed now if it hasn't been replaced in the queue
        return request == session.getAttribute(REQUEST_QUEUE);
    }

    /**
     * Put a new request in the queue.  This new request will replace
     * any other requests that were waiting.
     * 
     * @param request   The request to queue
     */
    private void enqueueRequest(HttpServletRequest request) {
        HttpSession session = request.getSession();

        // Put this request in the queue, replacing whoever was there before
        session.setAttribute(REQUEST_QUEUE, request);

        // if another request was waiting, notify it so it can discover that
        // it was replaced
        getSynchronizationObject(session).notify();
    }

    /**
     * What is the maximum wait time (in milliseconds) for this request
     * 
     * @param request
     * @return Maximum number of milliseconds to hold this request in the queue
     */
    private long getMaxWaitTime(HttpServletRequest request) {
        // look for a Pattern that matches the request's path
        String path = request.getRequestURI();
        for (Pattern p : maxWaitDurations.keySet()) {
            Matcher m = p.matcher(path);
            if (m.matches()) {
                // this pattern matches.  At most, how long can this request wait?
                Long maxDuration = (Long)maxWaitDurations.get(p);
                return maxDuration.longValue();
            }
        }
        // If no pattern matches the path, return the default value
        return DEFAULT_DURATION;
    }

    /**
     * Look through the filter's configuration, and determine whether or not it
     * should synchronize this request with others.
     *
     * @param httpRequest
     * @return
     */
    private boolean isFilteredRequest(HttpServletRequest request) {
        // iterate through the exclude patterns.  If one matches this path,
        // then the request is excluded.
        String path = request.getRequestURI();
        for (Pattern p : excludePatterns) {
            Matcher m = p.matcher(path);
            if(m.matches()) {
                // at least one of the patterns excludes this request
                return false;
            }
        }
        // this path is not excluded
        return true;
    }

    /** A list of Pattern objects that match paths to exclude */
    private LinkedList<Pattern> excludePatterns;

    /** A map from Pattern to max wait duration (Long objects) */
    private HashMap<Pattern,Long> maxWaitDurations; 

    /** The session attribute key for the request currently being processed */
    private final static String REQUEST_IN_PROCESS
    = "RequestControlFilter.requestInProcess";

    /** The session attribute key for the request currently waiting in the queue */
    private final static String REQUEST_QUEUE
    = "RequestControlFilter.requestQueue";

    /** The session attribute key for the synchronization object */
    private final static String SYNC_OBJECT_KEY = "RequestControlFilter.sessionSync";

    /** The default maximum number of milliseconds to wait for a request */
    private final static long DEFAULT_DURATION = 30000;
}