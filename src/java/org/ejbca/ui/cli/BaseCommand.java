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
import java.io.PrintStream;
import java.rmi.RemoteException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.ejb.CreateException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.InitialContextBuilder;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

/**
 * Base for Commands, contains useful functions
 *
 * @version $Id: BaseCommand.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public abstract class BaseCommand {
    /** Log4j instance for Base */
    private static Logger baseLog = Logger.getLogger(BaseAdminCommand.class);
    /** Log4j instance for actual class */
    private Logger log;

    /** UserAdminSession handle, not static since different object should go to different session beans concurrently */
    private IUserAdminSessionRemote cacheAdmin = null;
    /** Handle to AdminSessionHome */
    private static IUserAdminSessionHome cacheHome = null;
    /** RaAdminSession handle, not static since different object should go to different session beans concurrently */
    private IRaAdminSessionRemote raadminsession = null;
    /** Handle to RaAdminSessionHome */
    private static IRaAdminSessionHome raadminHomesession = null;    
    /** CAAdminSession handle, not static since different object should go to different session beans concurrently */
    private ICAAdminSessionRemote caadminsession = null;
    /** Handle to CertificateStoreSessionRemote, not static... */
    private ICertificateStoreSessionRemote certstoresession = null;
    /** Handle to PublisherSessionRemote, not static... */
    private IPublisherSessionRemote publishersession = null;
    
    protected Admin administrator = null;
    
    /** Where print output of commands */
    private PrintStream outStream = System.out;

    /** holder of argument array */
    protected String[] args = null;

    /**
     * Creates a new default instance of the class
     *
     */
    public BaseCommand() {
        init(null, Admin.TYPE_CACOMMANDLINE_USER, System.out);
    }

    /**
     * Initialize a new instance of BaseCommand
     *
     * @param args command line arguments
     * @param adminType type of admin Admin.TYPE_RACOMMANDLINE_USER, or Admin.TYPE_CACOMMANDLINE_USER
     * @param outStream stream where commands write its output
     */
    protected void init(String[] args, int adminType, PrintStream outStream) {
        log = Logger.getLogger(this.getClass());
        this.args = args;
        if( outStream != null ) {
          this.outStream = outStream;
        }
        administrator = new Admin(adminType);
    }

    /**
     * Gets InitialContext
     *
     * @return InitialContext
     */
    protected InitialContext getInitialContext() throws NamingException {
        baseLog.debug(">getInitialContext()");

        try {
            InitialContext cacheCtx = InitialContextBuilder.getInstance().getInitialContext();
            baseLog.debug("<getInitialContext()");
            return cacheCtx;
        } catch (NamingException e) {
            baseLog.error("Can't get InitialContext", e);
            throw e;
        }
    } // getInitialContext

    /** Gets CA admin session
     *@return ICAAdminSessionRemote
     */
    protected ICAAdminSessionRemote getCAAdminSessionRemote() throws Exception{
        if(caadminsession == null){
          Context ctx = getInitialContext();
          ICAAdminSessionHome home = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("CAAdminSession"), ICAAdminSessionHome.class );            
          caadminsession = home.create();          
        } 
        return caadminsession;
     } // getCAAdminSessionRemote

    /** Gets certificate store session
     *@return ICertificateStoreSessionRemote
     */
    protected ICertificateStoreSessionRemote getCertificateStoreSession() throws Exception{
        if(certstoresession == null){
          Context ctx = getInitialContext();
          ICertificateStoreSessionHome home = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );            
          certstoresession = home.create();          
        } 
        return certstoresession;
     } // getCertificateStoreSession
    
    /** Gets publisher session
     *@return ICertificateStoreSessionRemote
     */
    protected IPublisherSessionRemote getPublisherSession() throws Exception{
        if(publishersession == null){
          Context ctx = getInitialContext();
          IPublisherSessionHome home = (IPublisherSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("PublisherSession"), IPublisherSessionHome.class );            
          publishersession = home.create();          
        } 
        return publishersession;
     } // getPublisherSession
    /** Gets user admin session
     *@return InitialContext
     */
    protected IUserAdminSessionRemote getAdminSession()
        throws CreateException, NamingException, RemoteException {
        debug(">getAdminSession()");
        try {
            if (cacheAdmin == null) {
                if (cacheHome == null) {
                    Context jndiContext = getInitialContext();
                    Object obj1 = jndiContext.lookup("UserAdminSession");
                    cacheHome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                            IUserAdminSessionHome.class);
                }
                cacheAdmin = cacheHome.create();
            }
            debug("<getAdminSession()");
            return cacheAdmin;
        } catch (NamingException e) {
            error("Can't get Admin session", e);
            throw e;
        }
    } // getAdminSession
    
    /** Gets ra admin session
     *@return InitialContext
     */
    protected IRaAdminSessionRemote getRaAdminSession() throws CreateException, NamingException, RemoteException {
        debug(">getRaAdminSession()");
        administrator = new Admin(Admin.TYPE_RACOMMANDLINE_USER);
        try {
            if( raadminsession == null ) {
                if (raadminHomesession == null) {
                    Context jndiContext = getInitialContext();
                    Object obj1 = jndiContext.lookup("RaAdminSession");
                    raadminHomesession = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IRaAdminSessionHome.class);
                }
                raadminsession = raadminHomesession.create();
            }
            debug("<getRaAdminSession()");
            return  raadminsession;
        } catch (NamingException e ) {
            error("Can't get RaAdmin session", e);
            throw e;
        }
    } // getRaAdminSession    

    /**
     * Method checking if the application server is running.
     * 
     * @return true if app server is running.
     */
    protected boolean appServerRunning() {
        // Check that the application server is running by getting a home interface for user admin session
        try {
            Context ctx = getInitialContext();
            ICAAdminSessionHome home = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("CAAdminSession"),ICAAdminSessionHome.class);
            home.getClass(); // avoid PMD warning :)
            return true;
        } catch (Exception e) {
            error("Appserver not running: ", e);
            return false;
        }
    }

    /** Private key with length 1024 bits */
    static byte[] keys1024bit = Base64.decode(
    ("MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKA5rNhYbPuVcArT"
    +"mkthfrW2tX1Z7SkCD01sDYrkiwOcodFmS1cSyz8eHM51iwHA7CW0WFvfUjomBT5y"
    +"gRQfIsf5M5DUtYcKM1hmGKSPzvmF4nYv+3UBUesCvBXVRN/wFZ44SZZ3CVvpQUYb"
    +"GWjyC+Dgol5n8oKOC287rnZUPEW5AgMBAAECgYEAhMtoeyLGqLlRVFfOoL1cVGTr"
    +"BMp8ail/30435y7GHKc74p6iwLcd5uEhROhc3oYz8ogHV5W+w9zxKbGjU7b+jmh+"
    +"h/WFao+Gu3sSrZ7ieg95fSuQsBlJp3w+eCAOZwlEu/JQQHDtURui25SPVblZ9/41"
    +"u8VwFjk9YQx+nT6LclECQQDYlC9bOr1SWL8PBlipXB/UszMsTM5xEH920A+JPF4E"
    +"4tw+AHecanjr5bXSluRbWSWUjtl5LV2edqAP9EsH1/A1AkEAvWOctUvTlm6fWHJq"
    +"lZhsWVvOhDG7cn5gFu34J8JJd5QHov0469CpSamY0Q/mPE/y3kDllmyYvnQ+yobB"
    +"ZRg39QJBAINCM/0/eVQ58vlBKGTkL2pyfNYhapB9pjK04GWVD4o4j7CICfXjVYvq"
    +"eSq7RoTSX4NMnCLjyrRqQpHIxdxoE+0CQQCz7MzWWGF+Cz6LUrf7w0E8a8H5SR4i"
    +"GfnEDvSxIR2W4yWWLShEsIoEF4G9LHO5XOMJT3JOxIEgf2OgGQHmv2l5AkBThYUo"
    +"ni82jZuue3YqXXHY2lz3rVmooAv7LfQ63yzHECFsQz7kDwuRVWWRsoCOURtymAHp"
    +"La09g2BE+Q5oUUFx").getBytes());
    /** self signed cert done with above private key */
    static byte[] certbytes = Base64.decode(
    ("MIICNzCCAaCgAwIBAgIIIOqiVwJHz+8wDQYJKoZIhvcNAQEFBQAwKzENMAsGA1UE"
    +"AxMEVGVzdDENMAsGA1UEChMEVGVzdDELMAkGA1UEBhMCU0UwHhcNMDQwNTA4MDkx"
    +"ODMwWhcNMDUwNTA4MDkyODMwWjArMQ0wCwYDVQQDEwRUZXN0MQ0wCwYDVQQKEwRU"
    +"ZXN0MQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgbf2"
    +"Sv34lsY43C8WJjbUd57TNuHJ6p2Es7ojS3D2yxtzQg/A8wL1OfXes344PPNGHkDd"
    +"QPBaaWYQrvLvqpjKwx/vA1835L3I92MsGs+uivq5L5oHfCxEh8Kwb9J2p3xjgeWX"
    +"YdZM5dBj3zzyu+Jer4iU4oCAnnyG+OlVnPsFt6ECAwEAAaNkMGIwDwYDVR0TAQH/"
    +"BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0GA1UdDgQWBBQArVZXuGqbb9yhBLbu"
    +"XfzjSuXfHTAfBgNVHSMEGDAWgBQArVZXuGqbb9yhBLbuXfzjSuXfHTANBgkqhkiG"
    +"9w0BAQUFAAOBgQA1cB6wWzC2rUKBjFAzfkLvDUS3vEMy7ntYMqqQd6+5s1LHCoPw"
    +"eaR42kMWCxAbdSRgv5ATM0JU3Q9jWbLO54FkJDzq+vw2TaX+Y5T+UL1V0o4TPKxp"
    +"nKuay+xl5aoUcVEs3h3uJDjcpgMAtyusMEyv4d+RFYvWJWFzRTKDueyanw==").getBytes());

    /**
     * Method checking if strong crypto is installed (extra package from java.sun.com)
     * 
     * @return true if strong crypto is installed.
     */
    protected boolean strongCryptoInstalled() throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        CertTools.installBCProvider();
        X509Certificate cert = CertTools.getCertfromByteArray(certbytes);
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(keys1024bit);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFactory.generatePrivate(pkKeySpec);
        KeyStore ks = KeyTools.createP12("Foo", pk, cert, (X509Certificate)null);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // If password below is more than 7 chars, strong crypto is needed
        ks.store(baos, "foo1234567890".toCharArray());
        // If we didn't throw an exception, we were succesful
        return true;
    }

    /**
     * Logs a message with priority DEBUG
     *
     * @param msg Message
     */
    public void debug(String msg) {
        log.debug(msg);
    }

    /**
     * Logs a message and an exception with priority DEBUG
     *
     * @param msg Message
     * @param t Exception
     */
    public void debug(String msg, Throwable t) {
        log.debug(msg, t);
    }

    /**
     * Logs a message with priority INFO
     *
     * @param msg Message
     */
    public void info(String msg) {
        log.info(msg);
    }

    /**
     * Logs a message and an exception with priority INFO
     *
     * @param msg Message
     * @param t Exception
     */
    public void info(String msg, Throwable t) {
        log.info(msg, t);
    }

    /**
     * Logs a message with priority ERROR
     *
     * @param msg Message
     */
    public void error(String msg) {
        log.error(msg);
    }

    /**
     * Logs a message and an exception with priority ERROR
     *
     * @param msg Message
     * @param t Exception
     */
    public void error(String msg, Throwable t) {
        log.error(msg, t);
    }


    /**
     * Return the PrintStream used to print output of commands
     *
     */
    public PrintStream getOutputStream() {
        return outStream;
    }

    /**
     * Set the PrintStream used to print output of commands
     *
     * @param outStream stream where commands write its output
     */
    public void setOutputStream(PrintStream outStream) {
    if( outStream == null )
        this.outStream = System.out;
    else
        this.outStream = outStream;
    }   

} //BaseCommand
