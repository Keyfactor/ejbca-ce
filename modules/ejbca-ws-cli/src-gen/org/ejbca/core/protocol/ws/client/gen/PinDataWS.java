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

package org.ejbca.core.protocol.ws.client.gen;

/**
 * Deprecated class, kept for web service compatibility.
 * @deprecated
 * @version $Id$
 */
@Deprecated
public class PinDataWS {
	
	
	private int type = 0;
	private String initialPIN = null;
	private String PUK = null;
	
	/**
	 * Deprecated class, do not use.
	 * @deprecated
	 */
	@Deprecated
	public PinDataWS(){}
	
	/**
	 * Default constructor
	 * 
	 * @param type pnt of the PINTYPE_ constants
	 * @param initialPIN the initial pin of the token
	 * @param puk the puk of the token
	 */
	public PinDataWS(int type, String initialPIN, String puk) {
		super();
		this.type = type;
		this.initialPIN = initialPIN;
		PUK = puk;
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
		return PUK;
	}
	
	/**
	 * 
	 * @param puk the puk of the token
	 */
	public void setPUK(String puk) {
		PUK = puk;
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
