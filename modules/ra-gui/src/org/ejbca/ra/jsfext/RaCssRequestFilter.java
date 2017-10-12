package org.ejbca.ra.jsfext;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.RaCssInfo;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ra.RaAuthenticationHelper;



/**
 * 
 * Filter used to intercept the CSS request while loading RA-web. If the requesting administrator
 * belongs to a role which has a custom CSS set, it will be injected instead of the default one.
 * 
 * The modified (CSS) response will be browser cached as any other CSS, and the request for the 
 * CSS will not pass this filter until the browser invalidates the cache. Hence requests for the
 * modified CSS will not be requested via Peers for every request.
 * 
 * This filter is mapped in web.xml to only process CSS files in the RA-web.
 * 
 * @version $Id$
 *
 */
public class RaCssRequestFilter implements Filter {
    private final String CSS_INTERCEPT_PATH = "/ejbca/ra/css/w_e_style.css";
    private static Logger log = Logger.getLogger(RaCssRequestFilter.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    @EJB
    private WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;
    
    private RaAuthenticationHelper raAuthenticationHelper = null;
    private AuthenticationToken authenticationToken = null;
    private Map<AuthenticationToken, List<RaCssInfo>> cssCache;
    List<RaCssInfo> availableStyleSheets;
    
    @Override
    public void destroy() {
        //NOOP
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {
        // TODO This cache is very simple and remains its state until appserver restart... When a CSS is applied to a role in the adminweb,
        // a time stamp should be added which we can check when this filter is applied (which is when browser invalidates the CSS cache), 
        // before RaCssInfo is requested via Peers.
        cssCache = new HashMap<>();
        log.info(this.getClass().getName() + " initialized");        
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String requestPath = httpRequest.getRequestURI();
        if (requestPath.equals(CSS_INTERCEPT_PATH)) {
            authenticationToken = getAuthenticationToken(httpRequest, httpResponse);

            if (cssCache.containsKey(authenticationToken)) {
                availableStyleSheets = cssCache.get(authenticationToken);
            } else {
                // Check for modified CSS via Peers
                availableStyleSheets = raMasterApiProxyBean.getAvailableCustomRaCss(authenticationToken);
                cssCache.put(authenticationToken, availableStyleSheets);
            }
            if (availableStyleSheets == null) {
                // Stop here and pass on request (default CSS will be used)
                chain.doFilter(httpRequest, httpResponse);
                return;
            }
            
            PrintWriter clientPrintWriter = response.getWriter();
            try {
                ResponseWrapper responseWrapper = new ResponseWrapper((HttpServletResponse) response);
                chain.doFilter(httpRequest, responseWrapper);
                
                // TODO This has to handle multiple CSS in the case where the authToken belongs to multiple roles
                // once a 'Preferences' page is introduced to the RA-Web
                String newCssContent = new String(availableStyleSheets.get(0).getCssBytes());
                httpResponse.setContentType("text/css");
                httpResponse.setContentLength(newCssContent.length());
                clientPrintWriter.write(newCssContent);
            } finally {
                clientPrintWriter.close();
                
            }

        } else {
            // Pass on request
            chain.doFilter(httpRequest, httpResponse);
        }
    }


    /** @return the X509CertificateAuthenticationToken if the client has provided a certificate or a PublicAccessAuthenticationToken otherwise. */
    private AuthenticationToken getAuthenticationToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        // TODO This instantiated for every non-cached request for w_e_styles.css. Improvements  ? 
        raAuthenticationHelper = new RaAuthenticationHelper(webAuthenticationProviderSession);
        authenticationToken = raAuthenticationHelper.getAuthenticationToken(httpRequest, httpResponse);
        return authenticationToken;
    }
    
    
    public static class ResponseWrapper extends HttpServletResponseWrapper {
        private final CharArrayWriter writer;

        public ResponseWrapper(HttpServletResponse response) {
            super(response);
            writer = new CharArrayWriter();
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