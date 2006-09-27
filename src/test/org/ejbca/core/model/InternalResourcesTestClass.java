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
package org.ejbca.core.model;

import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;

import javax.ejb.EJBException;

import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/**
 * Class inheriting the internal resources class. and overloads the load
 * method in order to be used in a testscript
 * 
 * @author Philip Vendil 2006 sep 25
 *
 * @version $Id: InternalResourcesTestClass.java,v 1.1 2006-09-27 09:28:53 herrvendil Exp $
 */
public class InternalResourcesTestClass extends InternalResources {

	public InternalResourcesTestClass(){		
		String primaryLanguage = "se";
		String secondaryLanguage = "en";
		try {
		    InputStream primaryStream = new FileInputStream("src/intresources/intresources." + primaryLanguage + ".properties");
		    InputStream secondaryStream = new FileInputStream("src/intresources/intresources." + secondaryLanguage + ".properties");

			primaryResource.load(primaryStream);
			secondaryResource.load(secondaryStream);
		} catch (IOException e) {			
			throw new EJBException("Error reading internal resourcefile", e);
		}
		
	}
	
	/**
	 * Metod that returs a instance of the InternalResources
	 * might be null if load() haven't been called before this method.
	 */
	public static InternalResources getInstance(){
		if(instance == null){
			instance = new InternalResourcesTestClass();
		}
		return instance;
	}
}
