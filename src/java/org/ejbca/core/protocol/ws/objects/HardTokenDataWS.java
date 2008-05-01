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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Value object containing WS representation
 * of a hard token data it contains information
 * about PIN/PUK codes, hardtoken serial number
 * certificate stored on the card.
 * 
 * 
 * @author Philip Vendil
 *
 * $Id$
 */
public class HardTokenDataWS {


	private int tokenType = 0;
	private String label = null;
	private String hardTokenSN = null;
	private String copyOfSN = null;
	private List<String> copies = new ArrayList();
	private List<PINDataWS> pinDatas = new ArrayList();
	private List<Certificate> certificates = new ArrayList();
	private Date createTime = null;
	private Date modifyTime = null;
	
	private boolean encKeyKeyRecoverable = false;
	
	public HardTokenDataWS(){}
	
	/**
	 * Constuctor of a HardTokenDataWS with all it fields. This
	 * constructor should be used on the server side of EJBCA
	 * 
	 * @param tokenType one of the TOKENTYPE_ constants
	 * @param label indicating the use of the token, one of the LABEL_ constants
	 * @param hardTokenSN the SN of the hard token
	 * @param copyOfSN of this is a copy of another hard token, specify its SN otherwise use null.
	 * @param copies if there is copies of this hard token a list of serial number is specified.
	 * @param pinDatas a List of pin datas with PIN and PUK
	 * @param certificates the certificate stored on the token
	 * @param encKeyKeyRecoverable if the token have a special encryption key it should be specified if it is recoverable or not.
	 */
	public HardTokenDataWS(int tokenType, String label, String hardTokenSN, String copyOfSN, List<String> copies, List<PINDataWS> pinDatas, List<Certificate> certificates, boolean encKeyKeyRecoverable) {
		super();
		this.tokenType = tokenType;
		this.label = label;
		this.hardTokenSN = hardTokenSN;
		this.copyOfSN = copyOfSN;
		this.copies = copies;
		this.pinDatas = pinDatas;
		this.certificates = certificates;
		this.encKeyKeyRecoverable = encKeyKeyRecoverable;
	}

	/**
	 * Constuctor that should be used with the genTokenCertificates request
	 * 
	 * @param tokenType one of the TOKENTYPE_ constants
	 * @param label indicating the use of the token, one of the LABEL_ constants
	 * @param hardTokenSN the SN of the hard token
	 * @param copyOfSN of this is a copy of another hard token, specify its SN otherwise use null.
	 * @param pinDatas a List of pin datas with PIN and PUK
	 * @param encKeyKeyRecoverable if the token have a special encryption key it should be specified if it is recoverable or not.
	 */
	public HardTokenDataWS(int tokenType, String label, String hardTokenSN, String copyOfSN, List<PINDataWS> pinDatas, boolean encKeyKeyRecoverable) {
		super();
		this.tokenType = tokenType;
		this.label = label;
		this.hardTokenSN = hardTokenSN;
		this.copyOfSN = copyOfSN;
		this.pinDatas = pinDatas;
		this.encKeyKeyRecoverable = encKeyKeyRecoverable;
	}


	/**
	 * 
	 * @return a list WS representation of the stored certificates
	 */
	public List<Certificate> getCertificates() {
		return certificates;
	}

    /**
     * 
     * @param certificates a List of EJBCAWS Certificates stored on the token
     */
	public void setCertificates(List<Certificate> certificates) {
		this.certificates = certificates;
	}


	/**
	 * 
	 * @return >a list of hard token SN of copies that have been made of this token.
	 */
	public List<String> getCopies() {
		return copies;
	}

    /**
     * 
     * @param copies a list of hard token SN of copies that have been made of this token.
     */
	public void setCopies(List<String> copies) {
		this.copies = copies;
	}

    /**
     * 
     * @return a serial number of which this token is a copy of,  null if it isn't a copy
     */
	public String getCopyOfSN() {
		return copyOfSN;
	}

    /**
     * 
     * @param copyOfSN a serial number of which this token is a copy of,  null if it isn't a copy
     */
	public void setCopyOfSN(String copyOfSN) {
		this.copyOfSN = copyOfSN;
	}

    /**
     * 
     * @return true if the token have a separate encryption key and is key recoverable.
     */
	public boolean isEncKeyKeyRecoverable() {
		return encKeyKeyRecoverable;
	}

    /**
     * 
     * @param encKeyKeyRecoverable if the token have a separate encryption key and is key recoverable.
     */
	public void setEncKeyKeyRecoverable(boolean encKeyKeyRecoverable) {
		this.encKeyKeyRecoverable = encKeyKeyRecoverable;
	}

    /**
     * 
     * @return the serial number of the token
     */
	public String getHardTokenSN() {
		return hardTokenSN;
	}

    /**
     * 
     * @param hardTokenSN the serial number of the token
     */
	public void setHardTokenSN(String hardTokenSN) {
		this.hardTokenSN = hardTokenSN;
	}

    /**
     * 
     * @return list of PIN data containing PIN and PUK of the 
     */
	public List<PINDataWS> getPinDatas() {
		return pinDatas;
	}

    /**
     * 
     * @param pinDatas list of PIN data containing PIN and PUK of the
     */
	public void setPinDatas(List<PINDataWS> pinDatas) {
		this.pinDatas = pinDatas;
	}

    /**
     * 
     * @return one of the TOKENTYPE_ constants
     */
	public int getTokenType() {
		return tokenType;
	}

    /**
     * 
     * @param tokenType  one of the TOKENTYPE_ constants
     */
	public void setTokenType(int tokenType) {
		this.tokenType = tokenType;
	}

	/**
	 * @return the label indicating the use of the token, one of the LABEL_ constants
	 */
	public String getLabel() {
		return label;
	}
	

	/**
	 * @param the label indicating the use of the token, one of the LABEL_ constants
	 */
	public void setLabel(String label) {
		this.label = label;
	}

	/**
	 * 
	 * @return Returns the time this token was created
	 */
	public Date getCreateTime() {
		return createTime;
	}

	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}

	/**
	 * @return Returns the time this last was modified.
	 */
	public Date getModifyTime() {
		return modifyTime;
	}

	public void setModifyTime(Date modifyTime) {
		this.modifyTime = modifyTime;
	}
	
	
	
	
	
	
}
