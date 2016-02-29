package spnego;

/** 
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.HashMap;
import java.util.Map;

import java.util.logging.Logger;

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sourceforge.spnego.SpnegoAuthenticator;
import net.sourceforge.spnego.SpnegoHttpFilter.Constants;
import net.sourceforge.spnego.SpnegoHttpServletResponse;
import net.sourceforge.spnego.SpnegoPrincipal;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.ietf.jgss.GSSException;

public class ExampleSpnegoAuthenticatorValve extends AuthenticatorBase
{

    private static final Logger LOGGER = Logger.getLogger("SpnegoHttpFilter");
    private SpnegoAuthenticator authenticator = null;

    @Override
    protected final boolean authenticate(final Request request, final Response response, final LoginConfig config) throws IOException
    {
        LOGGER.fine("authenticate: request [" + request + "], config: [" + config + "]");

        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final SpnegoHttpServletResponse spnegoResponse = new SpnegoHttpServletResponse(
                (HttpServletResponse) response);

        final SpnegoPrincipal principal;

        try
        {
            principal = this.authenticator.authenticate(httpRequest, spnegoResponse);

        }
        catch (GSSException e)
        {
            throw new IOException(e);
        }
        LOGGER.fine("authenticate: principal [" + principal + "]");

        // context/auth loop not yet complete
        if (spnegoResponse.isStatusSet())
        {
            return false;
        }

        // assert
        if (null == principal)
        {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return false;
        }

        // now that we have a username, check if this username has any role(s) defined
        final Principal princ = this.context.getRealm().authenticate(
                principal.getName(), "");
//                "", "");

        if (null == princ)
        {
            // username may not have any roles or the wrong roles defined for the
            // the defined security realm (org.apache.catalina.Realm.java)
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }

        LOGGER.fine("authenticate: before register");
        this.register(request, response, princ, "SPNEGO", princ.getName(), "");

        return true;
    }

//    public PasswordAuthentication getPasswordAuthentication() {
//            // I haven't checked getRequestingScheme() here, since for NTLM
//            // and Negotiate, the usrname and password are all the same.
//            System.err.println("Feeding username and password for "
//               + getRequestingScheme());
//            return (new PasswordAuthentication(kuser, kpass.toCharArray()));
//        }
//    
    @Override
    public final void start() throws LifecycleException
    {
        LOGGER.fine("start");

        super.start();

        final Map<String, String> map = new HashMap<String, String>();
        map.put(Constants.ALLOW_BASIC, "true");
        map.put("spnego.allow.localhost", "true");
        map.put("spnego.allow.unsecure.basic", "true");
//        map.put("spnego.allow.unsecure.basic", "false");
        map.put("spnego.login.client.module", "spnego-client");
        map.put("spnego.krb5.conf", "krb5.conf");
        map.put("spnego.login.conf", "login.conf");
        map.put("spnego.preauth.username", "DPH4");
        map.put("spnego.preauth.password", "DPH1234!@#$");
//        map.put("spnego.preauth.username", "");
//        map.put("spnego.preauth.password", "");
        map.put("spnego.login.server.module", "spnego-server");
        map.put("spnego.prompt.ntlm", "true");
        map.put("spnego.allow.delegation", "true");
        map.put("spnego.logger.level", "1");

        try
        {
            authenticator = new SpnegoAuthenticator(map);
        }
        catch (LoginException e)
        {
            throw new LifecycleException(e);
        }
        catch (FileNotFoundException e)
        {
            throw new LifecycleException(e);
        }
        catch (GSSException e)
        {
            throw new LifecycleException(e);
        }
        catch (PrivilegedActionException e)
        {
            throw new LifecycleException(e);
        }
        catch (URISyntaxException e)
        {
            throw new LifecycleException(e);
        }
    }

    @Override
    public final void stop() throws LifecycleException
    {
        LOGGER.fine("stop");

        super.stop();

        if (null != this.authenticator)
        {
            this.authenticator.dispose();
        }
    }
}
