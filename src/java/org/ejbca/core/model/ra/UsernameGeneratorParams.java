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

package org.ejbca.core.model.ra;

import java.util.Arrays;
import java.util.List;

import org.ejbca.util.passgen.PasswordGeneratorFactory;

/** Parameters used in UsernameGenerator
 * 
 * @author tomas
 * @version $Id: UsernameGeneratorParams.java,v 1.1 2006-09-24 13:20:09 anatom Exp $
 * @see UsernameGenerator
 */
public class UsernameGeneratorParams {

	protected static final int MODE_RANDOM = 0;
	protected static final int MODE_USERNAME = 1;
	protected static final int MODE_DN = 2;

	public static final String RANDOM = "RANDOM";
	public static final String USERNAME = "USERNAME";
	public static final String DN = "DN";
	
	private String[] modes = {"RANDOM", "USERNAME", "DN"};
	private List modeList = null;

	// Generator configuration parameters, with good default values
	private int mode = MODE_RANDOM;
	private int randomNameLength = 12;
	private int randomGeneratorType = PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS;
	private String dNGeneratorComponent = "CN"; // Can be CN or UID
	private String prefix = null;
	private String postfix = null;
	private int randomPrefixLength = 12;
	
	public UsernameGeneratorParams() {
		// all defautl values
	}
	
	public String getDNGeneratorComponent() {
		return dNGeneratorComponent;
	}
	public void setDNGeneratorComponent(String generatorComponent) {
		dNGeneratorComponent = generatorComponent;
	}
	public String getPostfix() {
		return postfix;
	}
	public void setPostfix(String postfix) {
		this.postfix = postfix;
	}
	public String getPrefix() {
		return prefix;
	}
	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}
	public int getRandomGeneratorType() {
		return randomGeneratorType;
	}
	public void setRandomGeneratorType(int randomGeneratorType) {
		this.randomGeneratorType = randomGeneratorType;
	}
	public int getRandomNameLength() {
		return randomNameLength;
	}
	public void setRandomNameLength(int randomNameLength) {
		this.randomNameLength = randomNameLength;
	}
	public int getRandomPrefixLength() {
		return randomPrefixLength;
	}
	public void setRandomPrefixLength(int randomPrefixLength) {
		this.randomPrefixLength = randomPrefixLength;
	}

	public int getMode() {
		return mode;
	}

	public void setMode(int mode) {
		this.mode = mode;
	}

	public void setMode(String mode) {
		modeList = Arrays.asList(modes);
		if (!modeList.contains(mode)) {
			throw new IllegalArgumentException("Mode " + mode + " is not supported");
		}
		this.mode = modeList.indexOf(mode);
	}
	

}
