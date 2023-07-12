/**
 *  Software published by the Open Web Application Security Project (http://www.owasp.org)
 *  https://www.owasp.org/index.php/Content_Security_Policy
 *
 */

package org.owasp.filters;

import org.apache.commons.lang.StringUtils;
import org.ejbca.config.WebConfiguration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Sample filter implementation to define a set of Content Security Policies, and other security headers.<br/>
 *
 * This implementation has a dependency on Commons Codec API.<br/>
 *
 * This filter set CSP policies using all HTTP headers defined into W3C specification.<br/> and X-XSS-Protection,
 * X-Content-Type-Options, X-FRAME-OPTIONS <br/> This implementation is oriented to be easily understandable and easily
 * adapted.
 */
public class ContentSecurityPolicyFilter implements Filter {

    /**
     * Configuration member to specify if web app use web fonts Set to true to allow PrimeFaces to load icons, but only
     * allows loading locally.
     */
    public static final boolean APP_USE_WEBFONTS = true;

    private static final String CONTENT_SECURITY_POLICY = "Content-Security-Policy";
    private static final String X_CONTENT_SECURITY_POLICY = "X-Content-Security-Policy";

    /** Configuration member to specify if web app use videos or audios */
    public static final boolean APP_USE_AUDIOS_OR_VIDEOS = false;

    /** List CSP HTTP Headers */
    private final List<String> cspHeaders = new ArrayList<>();

    /** Collection of CSP polcies that will be applied */
    private String policies = null;

    /** which mode X-FRAME-OPTIONS should have, default DENY */
    private String frameOptionsMode = "DENY";

    /**
     * Used to prepare (one time for all) set of CSP policies that will be applied on each HTTP response.
     * 
     * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String plugins = filterConfig.getInitParameter("plugins");
        String objects = filterConfig.getInitParameter("objects");
        String unsafeeval = filterConfig.getInitParameter("unsafeeval");

        this.cspHeaders.add(CONTENT_SECURITY_POLICY);
        this.cspHeaders.add(X_CONTENT_SECURITY_POLICY);

        List<String> cspPolicies = new ArrayList<>();
        String originLocationRef = "'self'";
        cspPolicies.add("default-src 'none'");

        if (StringUtils.isNotEmpty(objects)) {
            cspPolicies.add("object-src " + originLocationRef);
        }
        cspPolicies.add("style-src " + originLocationRef+" 'unsafe-inline'");

        final String evalstr;
        if (StringUtils.isNotEmpty(unsafeeval)) {
            evalstr = " 'unsafe-eval'";
        } else {
            evalstr = "";
        }
        cspPolicies.add("script-src " + originLocationRef+" 'unsafe-inline'"+evalstr);
        cspPolicies.add("img-src " + originLocationRef);
        cspPolicies.add("frame-src 'self'");
        if (APP_USE_AUDIOS_OR_VIDEOS) {
            cspPolicies.add("media-src " + originLocationRef);
        }
        if (APP_USE_WEBFONTS) {
            cspPolicies.add("font-src " + originLocationRef);
        }
        cspPolicies.add("connect-src " + originLocationRef);
        cspPolicies.add("form-action " + originLocationRef);
        if (StringUtils.isNotEmpty(plugins)) {
            cspPolicies.add("plugin-types application/pdf");
        }
        cspPolicies.add("reflected-xss block");

        this.policies = normalizePolicies(cspPolicies);
        
        String mode = filterConfig.getInitParameter("frameoptionsmode");
        if ( mode != null ) {
            frameOptionsMode = mode;
        }
    }

    /**
     * Add CSP policies on each HTTP response.
     *
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain fchain) throws IOException, ServletException {
        HttpServletResponse httpResponse = ((HttpServletResponse) response);
        StringBuilder policiesBuffer = new StringBuilder(this.policies);
        for (String header : this.cspHeaders) {
            String configuredValue = WebConfiguration.getContentSecurityPolicy();
            httpResponse.setHeader(header, StringUtils.isNotBlank(configuredValue)
                    ? configuredValue
                    : policiesBuffer.toString());
        }
        // See https://www.owasp.org/index.php/List_of_useful_HTTP_headers
        // An information regarding X-XSS-Protection: https://blogs.msdn.microsoft.com/ie/2008/07/02/ie8-security-part-iv-the-xss-filter/
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
        // Also X-Content-Type-Options, see https://blogs.msdn.microsoft.com/ie/2008/09/02/ie8-security-part-vi-beta-2-update/
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        // Also X-FRAME-OPTIONS, see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
        // Used to be in a separate filter, ClickjackFilter, but there is no point in having multiple filters adding security headers
        httpResponse.setHeader("X-FRAME-OPTIONS", frameOptionsMode );
        // New header in 2018, Feature-Policy. https://scotthelme.co.uk/a-new-security-header-feature-policy/
        // https://github.com/w3c/webappsec-feature-policy/blob/master/features.md
        // https://w3c.github.io/webappsec-feature-policy/
        httpResponse.setHeader("Feature-Policy", "vibrate 'none'; autoplay 'none'; camera 'none'; microphone 'none'; midi 'none'; gyroscope 'none'; accelerometer 'none'; magnetometer 'none'; payment 'none'" );
        // Referrer policy: https://www.w3.org/TR/referrer-policy/
        httpResponse.setHeader("Referrer-Policy", "no-referrer-when-downgrade" );
        fchain.doFilter(request, response);
    }

    private String normalizePolicies(List<String> cspPolicies) {
        return cspPolicies
                .toString()
                .replaceAll("(\\[|\\])", StringUtils.EMPTY)
                .replace(",", ";")
                .trim();
    }

    /**
     * {@inheritDoc}
     * 
     * @see javax.servlet.Filter#destroy()
     */
    @Override
    public void destroy() {
        // Not used
    }
}
