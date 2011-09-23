/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.cli;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.util.EjbRemoteHelper;

/**
 * Base for Commands, contains useful functions
 * 
 * @version $Id$
 */
public abstract class BaseCommand implements CliCommandPlugin {

    public static final String USERNAME_FLAG = "-u";
    public static final String PASSWORD_FLAG = "-p";

    /** This helper will cache interfaces. Don't use static instantiation. */
    protected EjbRemoteHelper ejb = new EjbRemoteHelper();

    protected String cliUserName = null;
    protected String cliPassword = null;

    // private static Logger baseLog = Logger.getLogger(BaseCommand.class);
    private static Logger log = null;

    protected Logger getLogger() {
        if (log == null) {
            log = Logger.getLogger(this.getClass());
        }
        return log;
    }

    /**
     * In order to change the existing code as little as possible, this method takes the supplied args and extracts any found usernames and passwords
     * (and their respective flags), returns them as a tuplet and returns the args without those flags.
     * 
     * @param args the list of arguments
     * @return the array of arguments stripped of any supplied usernames or passwords. Returns an empty array if no username/password
     * can be established, which should be caught as an error in later code. 
     * @throws DefaultCliUserDisabledException if default CLI user was used, but is disabled
     * @throws NoCliUserProvidedException if no user was provided
     */
    protected String[] parseUsernameAndPasswordFromArgs(String[] args) {
        List<String> argsList = new ArrayList<String>(Arrays.asList(args));

        int index;
        if ((index = argsList.indexOf(USERNAME_FLAG)) != -1) {
            cliUserName = argsList.get(index + 1);
            argsList.remove(index + 1);
            argsList.remove(index);
        }
        if ((index = argsList.indexOf(PASSWORD_FLAG)) != -1) {
            cliPassword = argsList.get(index + 1);
            argsList.remove(index + 1);
            argsList.remove(index);
        }
        boolean defaultUserEnabled = ejb.getGlobalConfigurationSession().getCachedGlobalConfiguration().getEnableCommandLineInterfaceDefaultUser();      

        if ((cliUserName == null || cliPassword == null)) {
            if (defaultUserEnabled) {
                if (cliUserName == null) {
                    cliUserName = EjbcaConfiguration.getCliDefaultUser();
                }
                if (cliPassword == null) {
                    cliPassword = EjbcaConfiguration.getCliDefaultPassword();
                }
            } else {
                // throw new NoCliUserProvidedException("No CLI user provided and default CLI user is disabled.");
                getLogger().info("No CLI user was supplied, and use of the default CLI user is disabled.");
                getLogger().info("Please supply username and password in the command line with the syntax -u <username> -p <password>");
                getLogger().info("Password may be omitted to prompt.");
                return new String[0];
            }
        } else if (cliUserName.equals(EjbcaConfiguration.getCliDefaultUser()) && !defaultUserEnabled) {
            getLogger().info("CLI authentication using default user is disabled.");
            getLogger().info("Please supply username and password in the command line with the syntax -u <username> -p <password>");
            getLogger().info("Password may be omitted to prompt.");
            return new String[0];
        }

        return argsList.toArray(new String[argsList.size()]);
    }

    protected void logDefaultCliUserDisabled() {
        getLogger()
                .info("CLI authentication using default user is disabled.");
        getLogger().info("Please supply username and password in the command line with the syntax -u <username> -p <password>");
        getLogger().info("Password may be omitted to prompt.");
    }
    
    protected void logNoUserProvided() {
        getLogger().info("No CLI user was supplied, and use of the default CLI user is disabled.");
        getLogger().info("Please supply username and password in the command line with the syntax -u <username> -p <password>");
        getLogger().info("Password may be omitted to prompt.");
    }

    /**
     * This utility method gets an authenticated CliAuthenticationToken from the authentication service.
     * 
     * Worth noting in this method is that the password is not sent as a credential, because this would imply sending it (or its hash) in cleartext
     * over the network. Instead, it's only sent as part of a SHA1 hash (as part of the CliAuthenticationToken specification). Actual check of the
     * password's validity will formally occur at the first time that the authentication token is checked for authorization.
     * 
     * Note also that the CliAuthenticationToken may only be used for a single call via remote. I.e once it's passed through the network once, it's
     * invalid for further use.
     * 
     * @param username The main principal being requested
     * @param cleartextPassword The password in cleartext. While within the same call chain, there is little point in obfuscating it.
     * @return a single use CliAuthenticationToken.
     */
    protected AuthenticationToken getAdmin(String username, String cleartextPassword) {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new UsernamePrincipal(username));

        AuthenticationSubject subject = new AuthenticationSubject(principals, null);

        CliAuthenticationToken authenticationToken = (CliAuthenticationToken) ejb.getAuthenticationSession().authenticate(subject,
                ejb.getCliAuthenticationProvider());
        // Set hashed value anew in order to send back
        authenticationToken.setSha1HashFromCleartextPassword(cleartextPassword);
        return authenticationToken;
    }

    protected String getCommand() {
        return (getMainCommand() != null ? getMainCommand() + " " : "") + getSubCommand();
    }

    /**
     * Method checking if the application server is running.
     * 
     * @return true if app server is running.
     * 
     *         protected boolean appServerRunning() { // Check that the application server is running by getting a home // interface for user admin
     *         session
     * 
     *         // FIXME: The following will not comply after the EJB3 migration. The // below line needs to be resolved by some other means. -mikek
     *         try { ServiceLocator.getInstance().getRemoteHome(ICAAdminSessionHome.JNDI_NAME, ICAAdminSessionHome.class).getClass(); // avoid // PMD
     *         // warning // :) return true; } catch (Exception e) { baseLog.error("Appserver not running: ", e); return false; } }
     */

    /** Private key with length 1024 bits */
    static byte[] keys1024bit = Base64.decode(("MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKA5rNhYbPuVcArT"
            + "mkthfrW2tX1Z7SkCD01sDYrkiwOcodFmS1cSyz8eHM51iwHA7CW0WFvfUjomBT5y" + "gRQfIsf5M5DUtYcKM1hmGKSPzvmF4nYv+3UBUesCvBXVRN/wFZ44SZZ3CVvpQUYb"
            + "GWjyC+Dgol5n8oKOC287rnZUPEW5AgMBAAECgYEAhMtoeyLGqLlRVFfOoL1cVGTr" + "BMp8ail/30435y7GHKc74p6iwLcd5uEhROhc3oYz8ogHV5W+w9zxKbGjU7b+jmh+"
            + "h/WFao+Gu3sSrZ7ieg95fSuQsBlJp3w+eCAOZwlEu/JQQHDtURui25SPVblZ9/41" + "u8VwFjk9YQx+nT6LclECQQDYlC9bOr1SWL8PBlipXB/UszMsTM5xEH920A+JPF4E"
            + "4tw+AHecanjr5bXSluRbWSWUjtl5LV2edqAP9EsH1/A1AkEAvWOctUvTlm6fWHJq" + "lZhsWVvOhDG7cn5gFu34J8JJd5QHov0469CpSamY0Q/mPE/y3kDllmyYvnQ+yobB"
            + "ZRg39QJBAINCM/0/eVQ58vlBKGTkL2pyfNYhapB9pjK04GWVD4o4j7CICfXjVYvq" + "eSq7RoTSX4NMnCLjyrRqQpHIxdxoE+0CQQCz7MzWWGF+Cz6LUrf7w0E8a8H5SR4i"
            + "GfnEDvSxIR2W4yWWLShEsIoEF4G9LHO5XOMJT3JOxIEgf2OgGQHmv2l5AkBThYUo" + "ni82jZuue3YqXXHY2lz3rVmooAv7LfQ63yzHECFsQz7kDwuRVWWRsoCOURtymAHp"
            + "La09g2BE+Q5oUUFx").getBytes());
    /** self signed cert done with above private key */
    static byte[] certbytes = Base64.decode(("MIICNzCCAaCgAwIBAgIIIOqiVwJHz+8wDQYJKoZIhvcNAQEFBQAwKzENMAsGA1UE"
            + "AxMEVGVzdDENMAsGA1UEChMEVGVzdDELMAkGA1UEBhMCU0UwHhcNMDQwNTA4MDkx" + "ODMwWhcNMDUwNTA4MDkyODMwWjArMQ0wCwYDVQQDEwRUZXN0MQ0wCwYDVQQKEwRU"
            + "ZXN0MQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgbf2" + "Sv34lsY43C8WJjbUd57TNuHJ6p2Es7ojS3D2yxtzQg/A8wL1OfXes344PPNGHkDd"
            + "QPBaaWYQrvLvqpjKwx/vA1835L3I92MsGs+uivq5L5oHfCxEh8Kwb9J2p3xjgeWX" + "YdZM5dBj3zzyu+Jer4iU4oCAnnyG+OlVnPsFt6ECAwEAAaNkMGIwDwYDVR0TAQH/"
            + "BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0GA1UdDgQWBBQArVZXuGqbb9yhBLbu" + "XfzjSuXfHTAfBgNVHSMEGDAWgBQArVZXuGqbb9yhBLbuXfzjSuXfHTANBgkqhkiG"
            + "9w0BAQUFAAOBgQA1cB6wWzC2rUKBjFAzfkLvDUS3vEMy7ntYMqqQd6+5s1LHCoPw" + "eaR42kMWCxAbdSRgv5ATM0JU3Q9jWbLO54FkJDzq+vw2TaX+Y5T+UL1V0o4TPKxp"
            + "nKuay+xl5aoUcVEs3h3uJDjcpgMAtyusMEyv4d+RFYvWJWFzRTKDueyanw==").getBytes());

    /**
     * Method checking if strong crypto is installed (extra package from java.sun.com)
     * 
     * @return true if strong crypto is installed.
     */
    protected boolean strongCryptoInstalled() throws IOException, KeyStoreException, CertificateException, NoSuchProviderException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        CryptoProviderTools.installBCProvider();
        Certificate cert = CertTools.getCertfromByteArray(certbytes);
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(keys1024bit);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFactory.generatePrivate(pkKeySpec);
        KeyStore ks = KeyTools.createP12("Foo", pk, cert, (X509Certificate) null);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // If password below is more than 7 chars, strong crypto is needed
        ks.store(baos, "foo1234567890".toCharArray());
        // If we didn't throw an exception, we were succesful
        return true;
    }

}
