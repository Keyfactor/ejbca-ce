
package se.anatom.ejbca.ca.auth;

import java.net.*;
import java.rmi.*;
import java.io.*;

import javax.naming.*;
import javax.rmi.*;
import javax.ejb.*;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.AuthLoginException;

/**
 * Authenticates users towards a remote user database, using HTTP-based protocol.
 *
 * @version $Id: RemoteAuthenticationSessionBean.java,v 1.4 2002-06-04 13:59:55 anatom Exp $
 */
public class RemoteAuthenticationSessionBean extends BaseSessionBean {

    private static String REMOTE_PROTOCOL_VER = "1.0";

    /** URL to remote authentication server */
    String remoteurl = null;

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        // Get the URL from the environment from deployment descriptor
        remoteurl = (String)lookup("java:comp/env/AuthURL", java.lang.String.class);
        debug("<ejbCreate()");
    }

    /**
     * Implements IAuthenticationSession::authenticateUser.
     * Implements a mechanism that queries a remote database through a HTTP-based protocol.
     */
    public UserAuthData authenticateUser(String username, String password) throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        debug(">authenticateUser("+username+", hiddenpwd)");

        UserAuthData ret;
        try {
            ret = getDNfromRemote(REMOTE_PROTOCOL_VER, username, password);
        }
        catch (Exception e) {
            error("Authentication failed.", e);
            throw new EJBException(e);
        }
        // Only end users can be authenticated on remote database (so far...)
        ret.setType(SecConst.USER_ENDUSER);
        info("Autenticated user with dn \""+ ret.getDN()+"\" and email "+ret.getEmail());
        debug(">authenticateUser("+username+", hiddenpwd)");
        return ret;
    } // authenticateUser

    /**
     * Implements IAuthenticationSession::finishUser.
     * Does nothing!.
     */
    public void finishUser(String username, String password) throws ObjectNotFoundException {

    }

    /** Retieves user authentication data from a remote database using a simple HTTP-based protocol
     *  TODO: explain protocol
     * @param version verison of protocol
     * @param user username
     * @param password user's password
     * @return strnig contining the users DN
     * @exception IOException communication error
     * @exception NamingException cannot find AuthURL EJB-environment var
     *
     */
    private UserAuthData getDNfromRemote(String version, String user,
    String password ) throws NamingException, IOException {
        debug(">getDNfromRemote("+version+", "+user+", "+password+")");

        // Connect to url and do our stuff...
        URL url=new URL(remoteurl);
        HttpURLConnection connection = (HttpURLConnection)url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");

        {
            PrintWriter out = new PrintWriter(
            connection.getOutputStream());
            out.print("version=" + URLEncoder.encode(version)+'&');
            out.print("username=" + URLEncoder.encode(user)+'&');
            out.print("password=" + URLEncoder.encode(password));
            out.close();
        }

        BufferedReader in = new BufferedReader(
        new InputStreamReader(
        connection.getInputStream()));
        if ( in.readLine().indexOf("status=200 OK") >= 0 &&
        in.readLine().indexOf("result=grant") >= 0 ) {
            String dname="";
            String email=null;
            final String preFix="dn-";
            while( true ) {
                final String line=in.readLine();
                if ( line==null )
                    break;
                line.trim();
                if ( line.indexOf('=')>0 ) {
                    if ( line.indexOf(preFix)==0 )
                    {
                        if (line.substring(preFix.length()).indexOf("email") == 0) {
                            email = line.substring(preFix.length() + 6);
                        }
                        else {
                            if (dname.length()>0)
                                dname += ", ";
                            dname += line.substring(preFix.length());
                        }
                    }
                    else
                        dname += line;
                }
            }
            UserAuthData ret = new UserAuthData();
            ret.setDN(dname);
            ret.setEmail(email);
            debug("<getDNfromRemote");
            return ret;
        }
        debug("<getDNfromRemote");
        return null;
    } // getDNfromRemote

} // RemoteAuthenticationSessionBean
