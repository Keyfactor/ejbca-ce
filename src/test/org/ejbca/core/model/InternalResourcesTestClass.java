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


/**
 * Class inheriting the internal resources class. and overloads the load
 * method in order to be used in a testscript
 * 
 * @author Philip Vendil 2006 sep 25
 *
 * @version $Id: InternalResourcesTestClass.java,v 1.2 2006-10-23 16:25:11 anatom Exp $
 */
public class InternalResourcesTestClass extends InternalResources {

	public InternalResourcesTestClass(boolean test) {
		super(test);
	}
	
	/**
	 * Metod that returs a instance of the InternalResources
	 * might be null if load() haven't been called before this method.
	 */
	public static InternalResources getInstance(){
		if(instance == null){
			instance = new InternalResourcesTestClass(true);
		}
		return instance;
	}
}
