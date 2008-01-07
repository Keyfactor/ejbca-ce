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

package org.ejbca.core.protocol.ws.objects;

/**
 * Class containing a web service representation
 * of a PIN data such as type, PIN and PUK
 * 
 * 
 * @author Philip Vendil 2007 feb 8
 *
 * @version $Id: PINDataWS.java,v 1.3 2008-01-07 13:07:28 anatom Exp $
 */
public class PINDataWS {
	
	
	private int type = 0;
	private String initialPIN = null;
	private String pUK = null;
	
	public PINDataWS(){}
	
	/**
	 * Default constructor
	 * 
	 * @param type pnt of the PINTYPE_ constants
	 * @param initialPIN the initial pin of the token
	 * @param puk the puk of the token
	 */
	public PINDataWS(int type, String initialPIN, String puk) {
		super();
		this.type = type;
		this.initialPIN = initialPIN;
		pUK = puk;
	}
	
	/**
	 * @return the initial pin of the token
	 */
	public String getInitialPIN() {
		return initialPIN;
	}
	
	/**
	 * @param initialPIN the initial pin of the token
	 */
	public void setInitialPIN(String initialPIN) {
		this.initialPIN = initialPIN;
	}
	
	/**
	 * 
	 * @return  the puk of the token
	 */
	public String getPUK() {
		return pUK;
	}
	
	/**
	 * 
	 * @param puk the puk of the token
	 */
	public void setPUK(String puk) {
		pUK = puk;
	}
	
	/**
	 * 
	 * @return the type of PIN one of the PINTTYPE_ constants
	 */
	public int getType() {
		return type;
	}
	
	/**
	 * 
	 * @param type type of PIN one of the PINTTYPE_ constants
	 */
	public void setType(int type) {
		this.type = type;
	}

}
