/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.example.ejb;

import javax.ejb.Local;

import com.example.entity.MyCounterData;

/**
 * @version $Id$
 */
@Local
public interface  MySimpleBeanLocal  {

	public int updateCounter ();
	
	public MyCounterData getCurrent ();

	public void clearCounter();
	
}
