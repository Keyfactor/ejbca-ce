package se.anatom.ejbca.util;

import java.net.URL;
import java.util.Map;
import java.util.Collections;
import java.util.HashMap;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.Context;
import javax.rmi.PortableRemoteObject;
import javax.sql.DataSource;
import javax.ejb.EJBHome;
import javax.ejb.EJBLocalHome;

/**
 * A simple implementation of the ServiceLocator/HomeFactory J2EE Pattern.
 * {@link http://developer.java.sun.com/developer/restricted/patterns/ServiceLocator.html}
 *
 * It is used to look up JNDI related resources such as EJB homes, datasources, ...
 * @version $Id: ServiceLocator.java,v 1.1 2004-06-02 20:05:35 anatom Exp $
 */
public class ServiceLocator {

    /** ejb home cache */
    private transient Map ejbHomes = Collections.synchronizedMap(new HashMap());

    /** the jndi context */
    private transient Context ctx;

    /** the singleton instance */
    private static transient ServiceLocator instance;

    /**
     * Create a new service locator object.
     * @throws ServiceLocatorException if the context failed to be initialized
     */
    private ServiceLocator() throws ServiceLocatorException {
        try {
            this.ctx = new InitialContext();
        } catch (NamingException e){
            throw new ServiceLocatorException(e);
        }
    }

    /**
     * return the singleton instance
     * @return the singleton instance
     * @throws ServiceLocatorException if the instance could not be initialized the first time
     */
    public static final ServiceLocator getInstance() throws ServiceLocatorException {
        // synchronization is intentionally left out. It 'should' not have dramatic
        // consequences as it is not that destructive.
        if (instance == null){
            instance = new ServiceLocator();
        }
        return instance;
    }

    /**
     * return the ejb local home.
     * clients need to cast to the type of EJBHome they desire
     * @param jndiHomeName the jndi home name matching the requested local home.
     * @return the Local EJB Home corresponding to the home name
     */
    public EJBLocalHome getLocalHome(String jndiHomeName) throws ServiceLocatorException {
        EJBLocalHome home = (EJBLocalHome)ejbHomes.get(jndiHomeName);
        if (home == null) {
            try {
                home = (EJBLocalHome) ctx.lookup(jndiHomeName);
                ejbHomes.put(jndiHomeName, home);
            } catch (NamingException e) {
                throw new ServiceLocatorException(e);
            }
        }
        return home;
    }

    /**
     * return the ejb remote home.
     * clients need to cast to the type of EJBHome they desire
     * @param jndiHomeName the jndi home name matching the requested remote home.
     * @return the Local EJB Home corresponding to the home name
     */
    public EJBHome getRemoteHome(String jndiHomeName, Class className) throws ServiceLocatorException {
        EJBHome home = (EJBHome)ejbHomes.get(className);
        if (home == null) {
            try {
                Object objref = ctx.lookup(jndiHomeName);
                home = (EJBHome) PortableRemoteObject.narrow(objref, className);
                ejbHomes.put(className, home);
            } catch (NamingException e) {
                throw new ServiceLocatorException(e);
            }
        }
        return home;
    }

    /**
     * return the datasource object corresponding the the env entry name
     * @return the DataSource corresponding to the env entry name parameter
     * @throws ServiceLocatorException if the lookup fails
     */
    public DataSource getDataSource(String dataSourceName) throws ServiceLocatorException {
        try {
            return (DataSource)ctx.lookup(dataSourceName);
        } catch (NamingException e) {
            throw new ServiceLocatorException(e);
        }
    }

    /**
     * return the URL object corresponding to the env entry name
     * @param envName the env entry name
     * @return the URL value corresponding to the env entry name.
     * @throws ServiceLocatorException if the lookup fails
     */
    public URL getUrl(String envName) throws ServiceLocatorException {
        try {
            return (URL)ctx.lookup(envName);
        } catch (NamingException e) {
            throw new ServiceLocatorException(e);
        }
    }

    /**
     * return a boolean value corresponding to the env entry
     * @param envName the env entry name
     * @return the boolean value corresponding to the env entry.
     * @throws ServiceLocatorException if the lookup fails
     */
    public boolean getBoolean(String envName) throws ServiceLocatorException {
        try {
            return ((Boolean)ctx.lookup(envName)).booleanValue();
        } catch (NamingException e) {
            throw new ServiceLocatorException(e);
        }
    }

    /**
     * return a string value corresponding to the env entry
     * @param envName the env entry name
     * @return the boolean value corresponding to the env entry.
     * @throws ServiceLocatorException if the lookup fails
     */
    public String getString(String envName) throws ServiceLocatorException {
        try {
            return (String)ctx.lookup(envName);
        } catch (NamingException e) {
            throw new ServiceLocatorException(e);
        }
    }
}
