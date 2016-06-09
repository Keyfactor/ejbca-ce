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
package org.ejbca.core.model.era;

import java.io.Serializable;

/**
 * Serializable Tuple implementation.
 * 
 * @version $Id$
 */
public class Tuple<T extends Serializable> implements Serializable {

    private static final long serialVersionUID = 1L;

    private final int id;
	private final String name;
	private final T value;

	public Tuple(Integer id, String name, T value) {
		this.id = id;
		this.name = name;
		this.value = value;
	}

	public int getId() { return id; }
	public String getName() { return name; }
	public T getValue() { return value; }
}