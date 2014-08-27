/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections.map.ListOrderedMap;
import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;

/**
 * This file handles configuration from conf/extendedkeyusage.properties
 * 
 * @version $Id$
 */
public final class ExtendedKeyUsageConfiguration {

	private static final Logger log = Logger.getLogger(ExtendedKeyUsageConfiguration.class);
	
	/** This is a singleton so it's not allowed to create an instance explicitly */ 
	private ExtendedKeyUsageConfiguration() {}

    /**
     * Map for texts that maps OIDs in extendedKeyUsageOids to text strings that can be displayed.
     * If an extended key usage should not be displayed in the GUI, put null as value in the
     * properties file. This is done for deprecated IPSec key usages below. "IPSECENDSYSTEM",
     * "IPSECTUNNEL", "IPSECUSER".
     * 
     * The standard OIDs for extended key usages mostly comes from KeyPurposeId.id_kp_clientAuth
     * etc, or CertTools.EFS_OBJECTID, EFSR_OBJECTID, MS_DOCUMENT_SIGNING_OBJECTID, Intel_amt
     */
    private static Map<String, String> extendedKeyUsageOidsAndNames = null;
    
    /**
     * Array of all OIDs for Extended Key Usage, is filled by below and must therefore appear
     * before the below line in this file.
     */
    private static List<String> extendedKeyUsageOids = null;

    public static synchronized Map<String, String> getExtendedKeyUsageOidsAndNames() {
    	if (extendedKeyUsageOidsAndNames == null) {
    		fillExtendedKeyUsageOidsAndTexts();
    	}
		return extendedKeyUsageOidsAndNames;
	}
			
    public static synchronized List<String> getExtendedKeyUsageOids() {
    	if (extendedKeyUsageOids == null) {
    		fillExtendedKeyUsageOidsAndTexts();
    	}
		return extendedKeyUsageOids;
	}

    /**
     * Fill the map and list with OIDs from the configuration file
     */
	@SuppressWarnings("unchecked")
    private static synchronized void fillExtendedKeyUsageOidsAndTexts() {
    	final ListOrderedMap map = new ListOrderedMap();
    	final Configuration conf = ConfigurationHolder.instance();
    	final String ekuname = "extendedkeyusage.name.";
    	final String ekuoid = "extendedkeyusage.oid.";
    	for (int i = 0; i < 255; i++) {
    		final String oid = conf.getString(ekuoid+i);
    		if (oid != null) {
    			String name = conf.getString(ekuname+i);
    			if (name != null) {
    				// A null value in the properties file means that we should not use this value, so set it to null for real
    				if (name.equalsIgnoreCase("null")) {
    					name = null;
    				} else {
                        map.put(oid, name);    				    
    				}
    			} else {
    				log.error("Found extended key usage oid "+oid+", but no name defined. Not adding to list of extended key usages.");
    			}
    		} 
    		// No eku with a certain number == continue trying next, we will try 0-255.
    	}
        log.debug("Read "+map.size()+" extended key usages.");
    	extendedKeyUsageOids = map.asList();
    	if ((extendedKeyUsageOids == null) || (extendedKeyUsageOids.size() == 0)) {
    		log.error("Extended key usage OIDs is null or zero length, there is a serious error with extendedkeyusage.properties");
    		extendedKeyUsageOids = new ArrayList<String>();
    	}
    	extendedKeyUsageOidsAndNames = Collections.synchronizedMap(map);
    }

}
