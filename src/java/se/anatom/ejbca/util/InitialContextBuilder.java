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

package se.anatom.ejbca.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Hashtable;
import java.util.Properties;

import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * Utility class to manage creation of InitialContext.
 * <p/>
 *
 * @version $Id: InitialContextBuilder.java,v 1.2 2004-10-13 07:19:20 anatom Exp $
 */

public class InitialContextBuilder {
	/** Filename where find out jndi properties to apply */
	private final static String PROPERTIES = "ejbca.properties";

	/** Singleton instance */
	static private InitialContextBuilder instance = null;

	/** Cached properties found in ajbca.properties */
	private Properties cacheEnv = null;

	/** Cached context */
	private InitialContext cacheCtx = null;

    /**
     * Return the only instance permited of itself. It follow a Singleton design pattern.
     *
     * @return the instance
     */
	static public InitialContextBuilder getInstance() {
		if( instance == null ) {
			instance = new InitialContextBuilder();
		}
		return instance;
	}

    /**
     * Private constructor to avoid instance this class.
     */
	private InitialContextBuilder() {
		// try to load ejbca.properties into cacheEnv
		// it could be in any part of classpath
		try {	
			ClassLoader cl = ClassLoader.getSystemClassLoader();
			cacheEnv = new Properties();
			InputStream inStream = cl.getResourceAsStream(InitialContextBuilder.PROPERTIES);
			cacheEnv.load( inStream );	
			try { inStream.close(); } catch ( IOException ioex ) {}
		} catch (Exception ex2) {
			//ex2.printStackTrace();
			cacheEnv = null;
		}
	}

    /**
     * Return the configured context
     *
     * @return the requested context
     * @throws NamingException if there is an error creating the context
     */
	public InitialContext getInitialContext() throws NamingException {
		return getInitialContext(null);
	}

    /**
     * Return the requested context. 
	 * <p/>
	 * Try to use env to configure the context, if env is null, 
	 * try to use cacheEnv and if it is null too try to use jndi.propertied
     *
     * @param env the properties to configure the context.
     * @return the requested context
     * @throws NamingException if there is an error creating the datasource
     */
	public InitialContext getInitialContext(Hashtable env) throws NamingException {
		if( cacheCtx == null ) {
			if( env != null ) {
				// try the environmento given by the user
				cacheCtx = new InitialContext(env);
			} else if ( cacheEnv != null ) {
				// try ejbca.properties
				cacheCtx = new InitialContext(cacheEnv);
			} else {
				// try jndi.properties
				cacheCtx = new InitialContext();
			}
		} 
		return cacheCtx;
	}
}

// vi:ts=4 syntax=off