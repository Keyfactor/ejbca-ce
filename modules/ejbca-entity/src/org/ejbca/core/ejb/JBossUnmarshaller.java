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

package org.ejbca.core.ejb;

import java.io.Serializable;
import java.lang.reflect.Method;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.caadmin.CertificateProfileData;

/**
 * Helper class for extracting objects Serialized on JBoss under J2EE.
 * @version $Id$
 */
public class JBossUnmarshaller {
	
	private static final Logger log = Logger.getLogger(CertificateProfileData .class);

	private JBossUnmarshaller() {}

	/**
	 * Helper method for extracting objects Serialized on JBoss under J2EE.
	 * 
	 * The methods uses the fact that org.jboss.invocation.MarshalledValue is also a Serializable object
	 * and and extracts the real object from the MarshalledValue if this is passes as a parameter.
	 * Otherwise the object is returned in it's current form.
	 * 
	 * @param <T>  Class that we are trying to extract.
	 * @param t  Class that we are trying to extract.
	 * @param object An object implementing java.lang.Serializable interface
	 * @return The unmarshalled or original object of type T
	 */
	public static <T> T extractObject(Class<T> t, Serializable object) {
		T ret = null;
		String className = object.getClass().getName();
		if (className.equals(t.getName())) {
			// Return null, no update is needed
		} else if (className.equals("org.jboss.invocation.MarshalledValue")) {
			try {
				Method m = object.getClass().getMethod("get", new Class[0]);
				ret = (T) m.invoke(object, new Object[0]);
			} catch (Exception e) {
				log.error("", e);
			}
		} else {
			log.error("Extraction from " + className + " is currently not supported");
		}
		return ret;
	}
}
