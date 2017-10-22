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

import java.io.CharArrayWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.RaStyleInfo;
import org.cesecore.config.RaStyleInfo.RaCssInfo;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ra.RaAuthenticationHelper;



/**
 * 
 * Filter used to intercept the resource requests while loading RA-web. If the requesting administrator
 * belongs to a role which has a custom CSS or logo set, it will be injected instead of the default one.
 * 
 * The modified response will be browser cached as any other resource, and the request for 
 * it will not pass this filter until the browser invalidates the cache. Hence requests for the
 * modified resources will not be requested via Peers for every request.
 * 
 * This filter is mapped in web.xml to only process CSS / Image files in the RA-web.
 * 
 * @version $Id$
 *
 */
public class RaStyleRequestFilter implements Filter {
    private final String RA_LOGO_PATH = "/ejbca/ra/img/pk_logo.png";
    private static Logger log = Logger.getLogger(RaStyleRequestFilter.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    @EJB
    private WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;
    
    private RaAuthenticationHelper raAuthenticationHelper = null;
    private Map<AuthenticationToken, List<RaStyleInfo>> cssCache;
    
    @Override
    public void destroy() {
        //NOOP
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {
        // TODO Probably not necessary to query proxybean for every resource request in a page load (even though it is cached)
        cssCache = new HashMap<>();
        log.info(this.getClass().getName() + " initialized");        
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String requestPath = httpRequest.getRequestURI();
        String resource = requestPath.substring(requestPath.lastIndexOf('/') + 1, requestPath.length());
        List<RaStyleInfo> availableRaStyles;
        AuthenticationToken authenticationToken = null;
        authenticationToken = getAuthenticationToken(httpRequest, httpResponse);
        try {
            if (cssCache.containsKey(authenticationToken)) {
                List<RaStyleInfo> cachedStyles = cssCache.get(authenticationToken);
                // Check for changes
                availableRaStyles = raMasterApiProxyBean.getAvailableCustomRaStyles(authenticationToken, cachedStyles.hashCode());
                if (availableRaStyles == null) {
                    // No changes, use cache
                    availableRaStyles = cachedStyles;
                } else {
                    cssCache.put(authenticationToken, availableRaStyles);
                }
            } else {
                // Full reload of styles
                availableRaStyles = raMasterApiProxyBean.getAvailableCustomRaStyles(authenticationToken, 0);
                cssCache.put(authenticationToken, availableRaStyles);
            }
        } catch (Exception e) {
            // In any case of error loading the styles, display default style rather than no styles at all.
            chain.doFilter(httpRequest, httpResponse);
            return;
        }
        
        // TODO pure/base.css is currently unsupported for injection since it can't be differentiated from /css/base.css by name
        if (availableRaStyles.isEmpty() || requestPath.equals("/ejbca/ra/css/pure/base.css")) {
            // Stop here and pass on request (default CSS will be used)
            chain.doFilter(httpRequest, httpResponse);
            return;
        }
        // TODO This has to handle multiple styles in the case where the authToken belongs to multiple roles
        // once a 'Preferences' page is introduced to the RA-Web
        RaStyleInfo customResponse = availableRaStyles.get(0);
        if (requestPath.equals(RA_LOGO_PATH) && customResponse.getLogoBytes() != null) {
            OutputStream clientPrintWriter = response.getOutputStream();
            try {
                ResponseWrapper responseWrapper = new ResponseWrapper((HttpServletResponse) response);
                chain.doFilter(httpRequest, responseWrapper);
                
                byte[] newLogoContent = customResponse.getLogoBytes();
                httpResponse.setContentType(customResponse.getLogoContentType());
                httpResponse.setContentLength(newLogoContent.length);
                clientPrintWriter.write(newLogoContent);
            } finally {
                clientPrintWriter.close();
            }
            return;
        }
        
        for (RaCssInfo raCssInfo : customResponse.getRaCssInfos()) {
            if (raCssInfo.getCssName().equals(resource)) {
                PrintWriter clientPrintWriter = response.getWriter();
                try {
                    ResponseWrapper responseWrapper = new ResponseWrapper((HttpServletResponse) response);
                    chain.doFilter(httpRequest, responseWrapper);
                    String newCssContent = new String(raCssInfo.getCssBytes());
                    httpResponse.setContentType("text/css");
                    httpResponse.setContentLength(newCssContent.length());
                    clientPrintWriter.write(newCssContent);
                } finally {
                    clientPrintWriter.close();
                    
                }
                return;
            }
        }
        // No match. Pass on request
        chain.doFilter(httpRequest, httpResponse);
    }

    /** @return the X509CertificateAuthenticationToken if the client has provided a certificate or a PublicAccessAuthenticationToken otherwise. */
    private AuthenticationToken getAuthenticationToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        // TODO This instantiated for every non-cached request for w_e_styles.css. Improvements  ? 
        raAuthenticationHelper = new RaAuthenticationHelper(webAuthenticationProviderSession);
        AuthenticationToken authenticationToken = raAuthenticationHelper.getAuthenticationToken(httpRequest, httpResponse);
        return authenticationToken;
    }
    
    
    private class ResponseOutputStream extends ServletOutputStream {
        private ByteArrayOutputStream outStream = new ByteArrayOutputStream();

        @Override
        public void write(int writeByte) throws IOException {
            outStream.write(writeByte);
        }
    }
    
    private class ResponseWrapper extends HttpServletResponseWrapper {
        private final CharArrayWriter writer;
        private final ResponseOutputStream imageOutputStream;

        public ResponseWrapper(HttpServletResponse response) {
            super(response);
            writer = new CharArrayWriter();
            imageOutputStream = new ResponseOutputStream();
        }
        
        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            return imageOutputStream;
        }
        
        @Override
        public PrintWriter getWriter() throws IOException {
            return new PrintWriter(writer);
        }

        @Override
        public String toString() {
            return writer.toString();
        }
    }
}