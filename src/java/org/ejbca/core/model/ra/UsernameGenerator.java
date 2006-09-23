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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Class used to generate special usernames.
 * 
 * Configuration parameters:
 * 
 * NameGenerationScheme = "Which generation scheme should be used, RANDOM, USERNAME or DN"
 * RANDOM will generate a random username with length set in 'randomNameLength'.
 *   
 * NameGenerationParameters = "Parameters for name generation, for DN it can be CN or UID". 
 * If mode is DN, the CN or UID is taken from the DN to be used as username (adding pre- and postfix off-course).
 *   
 * NameGenerationPrefix = "Prefix to generated name, a string that can contain the variable ${RANDOM}"
 * exmaple: "Prefix - "
 *   
 * NameGenerationPostfix="Postfix to generated name, a string that can contain the variable ${RANDOM}"
 * example: " - Postfix"
 * 
 * The variable ${RANDOM} will be replaced by a random value of length set in 'randomPrefixLength'. 
 * 
 * @author tomas
 * @version $Id: UsernameGenerator.java,v 1.1 2006-09-23 07:26:28 anatom Exp $
 */
public class UsernameGenerator {

	private static Logger log = Logger.getLogger(UsernameGenerator.class);

	private static final int MODE_RANDOM = 0;
	private static final int MODE_USERNAME = 1;
	private static final int MODE_DN = 2;

	public static final String RANDOM = "RANDOM";
	public static final String USERNAME = "USERNAME";
	public static final String DN = "DN";
	
	private String[] modes = {"RANDOM", "USERNAME", "DN"};
	private List modeList = null;
	private int mode = -1;
	
	// Generator configuration parameters, with good default values
	private int randomNameLength = 12;
	private int randomGeneratorType = PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS;
	private String dNGeneratorComponent = "CN"; // Can be CN or UID
	private String prefix = null;
	private String postfix = null;
	private int randomPrefixLength = 12;
	
	public static UsernameGenerator getInstance(String mode) {
		return new UsernameGenerator(mode);
	}
	private UsernameGenerator(String mode) {
		modeList = Arrays.asList(modes);
		if (!modeList.contains(mode)) {
			throw new IllegalArgumentException("Mode " + mode + " is not supported");
		}
		this.mode = modeList.indexOf(mode);
	}
	
	public String generateUsername() {
		String ret = null;
		if (mode != MODE_RANDOM) {
			throw new IllegalArgumentException("generateUsername() can only be used in mode RANDOM");
		}
		ret = getRandomString(randomNameLength);
		log.debug("Generated random username: "+ret);
		return addPrePostFix(ret);
	}
	
	public String generateUsername(String name) {
		String str = name;
		if (mode == MODE_RANDOM) {
			throw new IllegalArgumentException("generateUsername(String) can only be used in mode DN ur USERNAME");
		} else if (mode == MODE_DN) {
	        str = CertTools.getPartFromDN(name, dNGeneratorComponent);			
		} else if (mode == MODE_USERNAME) {}
		return addPrePostFix(str);
	}
	
	private String getRandomString(int length) {
		IPasswordGenerator gen = PasswordGeneratorFactory.getInstance(randomGeneratorType);
		return gen.getNewPassword(length, length);		
	}
	
	private String addPrePostFix(String in) {
		String ret = in;
		String pre = getPrefix();
		String post = getPostfix();
		if (pre != null) {
			ret = pre + ret;
		}
		if (post != null) {
			ret = ret + post;
		}
		return ret;
	}

	private String getPostfix() {
		return interpolate(postfix);
	}

	public void setPostfix(String postfix) {
		this.postfix = postfix;
	}

	private String getPrefix() {
		return interpolate(prefix);
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}
	
    /** regexp pattern to match ${identifier} patterns */
    private final static Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}");
    /**
     * Interpolate the patterns that exists on the input on the form '${pattern}'.
     * @param input the input content to be interpolated
     * @return the interpolated content
     */
    private String interpolate(String input) {
    	if (input == null)
    		return null;
        final Matcher m = PATTERN.matcher(input);
        final StringBuffer sb = new StringBuffer(input.length());
        while (m.find()) {
            // when the pattern is ${identifier}, group 0 is 'identifier'
            String key = m.group(1);
            String value = null;
            if (StringUtils.equals(key, "RANDOM")) {
            	value = getRandomString(randomPrefixLength);
            }
            // if the pattern does exists, replace it by its value
            // otherwise keep the pattern ( it is group(0) )
            if (value != null) {
                m.appendReplacement(sb, value);
            } else {
                // I'm doing this to avoid the backreference problem as there will be a $
                // if I replace directly with the group 0 (which is also a pattern)
                m.appendReplacement(sb, "");
                String unknown = m.group(0);
                sb.append(unknown);
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

	public void setRandomPrefixLength(int length) {
		this.randomPrefixLength = length;
	}

	public void setDNGeneratorComponent(String generatorComponent) {
		dNGeneratorComponent = generatorComponent;
	}
	public void setRandomNameLength(int randomNameLength) {
		this.randomNameLength = randomNameLength;
	}

}
