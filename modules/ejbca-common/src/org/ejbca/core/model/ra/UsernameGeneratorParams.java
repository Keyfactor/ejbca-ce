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

import org.ejbca.core.model.UsernameGenerateMode;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Parameters used in UsernameGenerator
 * 
 * @version $Id$
 * @see UsernameGenerator
 */
public class UsernameGeneratorParams {

	// Generator configuration parameters, with good default values
	private UsernameGenerateMode mode = UsernameGenerateMode.RANDOM;
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

	public UsernameGenerateMode getMode() {
		return mode;
	}

	public void setMode(String mode) {
		UsernameGenerateMode.fromString(mode)
				.ifPresentOrElse( item ->  this.mode = item,
						() -> {throw new IllegalArgumentException("Mode " + mode + " is not supported");}
				);

	}
}
