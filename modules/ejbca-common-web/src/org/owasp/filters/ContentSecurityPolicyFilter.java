/**
 *  Software published by the Open Web Application Security Project (http://www.owasp.org)
 *  https://www.owasp.org/index.php/Content_Security_Policy
 *
 */

package org.owasp.filters;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;

/**
 * Sample filter implementation to define a set of Content Security Policies.<br/>
 * 
 * This implementation has a dependency on Commons Codec API.<br/>
 * 
 * This filter set CSP policies using all HTTP headers defined into W3C specification.<br/>
 * <br/>
 * This implementation is oriented to be easily understandable and easily adapted.<br/>
 * 
 * @version $Id$
 */
public class ContentSecurityPolicyFilter implements Filter {

    /** Configuration member to specify if web app use web fonts */
    public static final boolean APP_USE_WEBFONTS = false;

    /** Configuration member to specify if web app use videos or audios */
    public static final boolean APP_USE_AUDIOS_OR_VIDEOS = false;

    /** List CSP HTTP Headers */
    private List<String> cspHeaders = new ArrayList<String>();

    /** Collection of CSP polcies that will be applied */
    private String policies = null;

    /** Used for Script Nonce */
    //private SecureRandom prng = null;

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

        // Init secure random
        /*
        try {
            this.prng = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new ServletException(e);
        }
        */

        // Define list of CSP HTTP Headers
        // Used by all modern real browsers
        this.cspHeaders.add("Content-Security-Policy");
        // Used by IE10 that partially implements CSP
        this.cspHeaders.add("X-Content-Security-Policy");

        // Define CSP policies
        // Loading policies for Frame and Sandboxing will be dynamically defined : We need to know if context use Frame
        List<String> cspPolicies = new ArrayList<String>();
        String originLocationRef = "'self'";
        // --Disable default source in order to avoid browser fallback loading using 'default-src' locations
        cspPolicies.add("default-src 'none'");
        // --Define loading policies for Objects (<object> tags)
        if (StringUtils.isNotEmpty(objects)) {
            cspPolicies.add("object-src " + originLocationRef);
        }
        // --Define loading policies for Styles (CSS), allow inline style elements
        cspPolicies.add("style-src " + originLocationRef+" 'unsafe-inline'");
        // --Define loading policies for javascript, allow inline style elements in order to use onClick attributes
        final String evalstr;
        if (StringUtils.isNotEmpty(unsafeeval)) {
            evalstr = " 'unsafe-eval'";
        } else {
            evalstr = "";
        }
        cspPolicies.add("script-src " + originLocationRef+" 'unsafe-inline'"+evalstr);
        // --Define loading policies for Images
        cspPolicies.add("img-src " + originLocationRef);
        // Frame + Sandbox : Here sandbox allow nothing, customize sandbox options depending on your app....
        //policiesBuffer.append(";").append("frame-src 'self';sandbox");
        cspPolicies.add("frame-src 'self'");
        // --Define loading policies for Audios/Videos
        if (APP_USE_AUDIOS_OR_VIDEOS) {
            cspPolicies.add("media-src " + originLocationRef);
        }
        // --Define loading policies for Fonts
        if (APP_USE_WEBFONTS) {
            cspPolicies.add("font-src " + originLocationRef);
        }
        // --Define loading policies for Connection, which we don't use, but may use when we move to advanced JSF pages and components
        cspPolicies.add("connect-src " + originLocationRef);
        // --Define loading policies for Form
        cspPolicies.add("form-action " + originLocationRef);
        // --Define loading policies for Plugins Types, only allow PDF documents, if plug-ins are enabled in web.xml
        if (StringUtils.isNotEmpty(plugins)) {
            cspPolicies.add("plugin-types application/pdf");
        }
        // --Define browser XSS filtering feature running mode
        cspPolicies.add("reflected-xss block");

        // Target formating
        this.policies = cspPolicies.toString().replaceAll("(\\[|\\])", "").replaceAll(",", ";").trim();
    }

    /**
     * Add CSP policies on each HTTP response.
     * 
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain fchain) throws IOException, ServletException {
        //HttpServletRequest httpRequest = ((HttpServletRequest) request);
        HttpServletResponse httpResponse = ((HttpServletResponse) response);

        /* Step 1 : Detect if target resource is a Frame */
        // Customize here according to your context...

        /* Step 2 : Add CSP policies to HTTP response */
        StringBuilder policiesBuffer = new StringBuilder(this.policies);

        // Add Script Nonce CSP Policy
        // With this:
        // Content security policy script-nonce. Only javascripts that are in a self-source js file, or in-line and declare a nonce 
        // will be allowed to execute in the browser when the content-security-policy headers are defined with 
        // "script-src 'self' 'nonce-$RANDOM". 
        // The RANDOM is passed in each request as an attribute CSP_SCRIPT_NONCE. See ContentSecurityPolicyFilter.java
        // Add nonce to in-line java scripts like:
        // <script nonce="<%= (String)request.getAttribute("CSP_SCRIPT_NONCE") %>" type="text/javascript">
        
        // We can not use this currently because it would require moving all <a id="item-id" ...onclick="callMethod()"/> into setting event handlers in the javascript methods instead:
        // document.getElementById('item-id').onclick = callMethod();
        /*
        // Set nonce in session variable instead of on the request only
        // This is needed because EJBCA uses frames. If/when we do not use frames anymore we can simply set the nonce in every request
        // httpRequest.setAttribute("CSP_SCRIPT_NONCE", scriptNonce);
        HttpSession session = httpRequest.getSession(false);
        final String scriptNonce;
        if ((session == null) || (session.getAttribute("CSP_SCRIPT_NONCE") == null)) {
            // Generate a new random nonce
            // --Generate a random number
            String randomNum = new Integer(this.prng.nextInt()).toString();
            // --Get its digest
            MessageDigest sha;
            try {
                sha = MessageDigest.getInstance("SHA-1");
            }
            catch (NoSuchAlgorithmException e) {
                throw new ServletException(e);
            }
            byte[] digest = sha.digest(randomNum.getBytes());
            // --Encode it into HEXA
            scriptNonce = Hex.encodeHexString(digest);
            // Old style, pre-draft standard "script-nonce" directive"
            //policiesBuffer.append(";").append("script-nonce ").append(scriptNonce);
            // Standard script-src directive, including nonce
            /// Content-Security-Policy: script-src 'self' 'nonce-$RANDOM';
            // Allow all inline javascript with 'unsafe-inline' and 'unsafe-eval'
            //policiesBuffer.append(";script-src 'self' 'unsafe-inline' 'unsafe-eval'");
            // Only allow in-line javascript with nonces
            // --Made available script nonce in view app layer, so we can include it in scripts by retrieving this parameter
            //httpRequest.setAttribute("CSP_SCRIPT_NONCE", scriptNonce);
            if (session == null) {
                session = httpRequest.getSession();
            }
            session.setAttribute("CSP_SCRIPT_NONCE", scriptNonce);
        } else {
            scriptNonce = (String)session.getAttribute("CSP_SCRIPT_NONCE");
            
        }
        policiesBuffer.append("; script-src 'self' 'nonce-").append(scriptNonce).append("'");
        */
        
        // Add policies to all HTTP headers
        for (String header : this.cspHeaders) {
            httpResponse.setHeader(header, policiesBuffer.toString());
        }
        // Also add X-XSS-Protection, newer header. 
        // See https://www.owasp.org/index.php/List_of_useful_HTTP_headers
        // https://blogs.msdn.microsoft.com/ie/2008/07/02/ie8-security-part-iv-the-xss-filter/
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
        // Also X-Content-Type-Options, see https://blogs.msdn.microsoft.com/ie/2008/09/02/ie8-security-part-vi-beta-2-update/
        if ( httpResponse.getContentType() == null || (!httpResponse.getContentType().equalsIgnoreCase("text/vbscript") && !httpResponse.getContentType().equalsIgnoreCase("text/vbs")) ) {
            httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        }
        
        /* Step 3 : Let request continue chain filter */
        fchain.doFilter(request, response);
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