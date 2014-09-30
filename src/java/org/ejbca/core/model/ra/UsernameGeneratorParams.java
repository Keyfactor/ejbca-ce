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

package org.ejbca.core.model.ra;

import java.util.Arrays;
import java.util.List;

import org.ejbca.util.passgen.PasswordGeneratorFactory;

/** Parameters used in UsernameGenerator
 * 
 * @version $Id$
 * @see UsernameGenerator
 */
public class UsernameGeneratorParams {

	/** Create a completely random username */
	protected static final int MODE_RANDOM = 0;
	/** Use the input as the base username */
	protected static final int MODE_USERNAME = 1;
	/** Use a part of the DN as pase username */
	protected static final int MODE_DN = 2;
	/** use a fixed (set as dNGeneratorComponent) username */
	protected static final int MODE_FIXED = 3;

	public static final String RANDOM = "RANDOM";
	public static final String USERNAME = "USERNAME";
	public static final String DN = "DN";
	public static final String FIXED = "FIXED";
	
	private String[] modes = {"RANDOM", "USERNAME", "DN", "FIXED"};

	// Generator configuration parameters, with good default values
	private int mode = MODE_RANDOM;
	private int randomNameLength = 12;
	private String randomGeneratorType = PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS;
	private String dNGeneratorComponent = "CN"; // Can be CN, UID, SN etc, or CN;UID;SN
	private String prefix = null;
	private String postfix = null;
	private int randomPrefixLength = 12;
	
	public UsernameGeneratorParams() {
		// all default values
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
	public String getRandomGeneratorType() {
		return randomGeneratorType;
	}
	public void setRandomGeneratorType(String randomGeneratorType) {
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
	    final List<String> modeList = Arrays.asList(modes);
		if (!modeList.contains(mode)) {
			throw new IllegalArgumentException("Mode " + mode + " is not supported");
		}
		this.mode = modeList.indexOf(mode);
	}
	

}
