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
package com.example.entity;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "MyCounterData")
/**
 * @version $Id$
 */
public class MyCounterData implements Serializable {

    private static final long serialVersionUID = -8493105317760641442L;

    private int pk;
    private int counter;
    
    public void setPk (int pk) { this.pk = pk; }
	public int getPk () { return pk; }
	
    public void setCounter (int counter) { this.counter = counter; }
	public int getCounter () { return counter; }

}
