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

package org.ejbca.util.dn;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Name;

/** Class holding information and utilitites for handling different DN components, CN, O etc
 * 
 * @author tomas
 * @version $Id: DnComponents.java,v 1.2 2006-11-22 08:36:14 anatom Exp $
 */
public class DnComponents {
    private static Logger log = Logger.getLogger(DnComponents.class);

    private static DnComponents obj = new DnComponents();
    
    /** BC X509Name contains some lookup tables that could maybe be used here. */
    private static HashMap oids = new HashMap();

    // Default values
    static {
        oids.put("c", X509Name.C);
        oids.put("dc", X509Name.DC);
        oids.put("st", X509Name.ST);
        oids.put("l", X509Name.L);
        oids.put("o", X509Name.O);
        oids.put("ou", X509Name.OU);
        oids.put("t", X509Name.T);
        oids.put("surname", X509Name.SURNAME);
        oids.put("initials", X509Name.INITIALS);
        oids.put("givenname", X509Name.GIVENNAME);
        oids.put("gn", X509Name.GIVENNAME);
        oids.put("sn", X509Name.SN);
        oids.put("serialnumber", X509Name.SN);
        oids.put("cn", X509Name.CN);
        oids.put("uid", X509Name.UID);
        oids.put("emailaddress", X509Name.EmailAddress);
        oids.put("e", X509Name.EmailAddress);
        oids.put("email", X509Name.EmailAddress);
        oids.put("unstructuredname", X509Name.UnstructuredName); //unstructuredName 
        oids.put("unstructuredaddress", X509Name.UnstructuredAddress); //unstructuredAddress
    }
    // Default values
    private static String[] dNObjectsForward = {
        "unstructuredaddress", "unstructuredname", "emailaddress", "e", "email", "uid", "cn", "sn", "serialnumber", "gn", "givenname",
        "initials", "surname", "t", "ou", "o", "l", "st", "dc", "c"
    };
    // Default values    
    private static String[] dNObjectsReverse = null;
    
    // Load values from a properties file, if it exists
    static {
        DnComponents.load();
    }
    /** This property is true if reverse DN order should be used. Default value is false (forward order).
     * This setting is changed from ejbca.properties
     */
    private static final boolean reverseOrder = BooleanUtils.toBoolean("@certtools.dnorderreverse@");
    
    
    public static DERObjectIdentifier getOid(String o) {
        return (DERObjectIdentifier) oids.get(o.toLowerCase());
    } // getOid

    /**
     * Returns the dnObject (forward or reverse) that is in use
     */
    public static String[]getDnObjects() {
        if (!reverseOrder) {
            return dNObjectsForward;
        }
        return getDnObjectsReverse();
    }
    
    /**
     * Returns the reversed dnObjects.
     * Protected to allow testing
     */
    protected static String[] getDnObjectsReverse() {
        // Create and reverse the order if it has not been initialized already
        if (dNObjectsReverse == null) {
            dNObjectsReverse = dNObjectsForward.clone();
            ArrayUtils.reverse(dNObjectsReverse);
        }
        return dNObjectsReverse;
    }
    
    private static void load() {
        // Read the file to an array of lines 
        String line;
        LinkedHashMap map = new LinkedHashMap();
        BufferedReader in = null;
        InputStreamReader inf = null;
        try
        {    
            InputStream is = obj.getClass().getResourceAsStream("/dncomponents.properties");
            //log.info("is is: " + is);
            if (is != null) {
                inf = new InputStreamReader(is);
                //inf = new FileReader("c:\\foo.properties");
                in = new BufferedReader(inf);
                if (!in.ready())
                    throw new IOException();
                String[] splits = null;
                while ((line = in.readLine()) != null) {
                    splits = StringUtils.split(line, '=');
                    if ( (splits != null) && (splits.length > 1) ) {
                        String name = splits[0]; 
                        DERObjectIdentifier oid = new DERObjectIdentifier(splits[1]);
                        map.put(name, oid);
                    }
                }
                in.close();
                // Now we have read it in, transfer it to the main oid map
                log.info("Using DN components from properties file");
                oids.clear();
                oids.putAll(map);
                Set keys = map.keySet();
                /*
                Iterator keyIter = keys.iterator();
                while (keyIter.hasNext()) {
                    System.out.println((String)keyIter.next());
                }
                Collection values = map.values();
                Iterator valueIter = values.iterator();
                while (valueIter.hasNext()) {
                    DERObjectIdentifier oid = (DERObjectIdentifier)valueIter.next();
                    System.out.println(oid.getId());
                }
                */
                // Set the maps to the desired ordering
                dNObjectsForward = (String[])keys.toArray(new String[0]);                
            } else {
                log.debug("Using default values for DN components");                
            }
        }
        catch (IOException e) {
            log.debug("Using default values for DN components");
        } finally {
            try {
                if (inf != null) inf.close();
                if (in != null) in.close();                
            } catch (IOException e) {}
        }

    }

}
