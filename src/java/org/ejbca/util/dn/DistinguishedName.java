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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Collections;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/** This class aims to be DN representation.
 * It offers facilities to merge two DN.
 * @author David Galichet
 * @version $Id$
 */
public class DistinguishedName extends LdapName {

    Logger logger = Logger.getLogger(DistinguishedName.class.getName());

    /** Public constructor.
     * @param rdns list of relative Distinguished Names.
     */
    public DistinguishedName(List rdns) {
        super(rdns);
    }

    /** Public constructor.
     * @param name Distinguished Name.
     * @throws javax.naming.InvalidNameException in case of invalid name.
     */
    public DistinguishedName(String name) throws InvalidNameException {
        super(name);
    }

    /** Get a relative Distinguished Name.
     * this method get the first occurence in the case of mulitple.
     * @param type type of the DN.
     * @return the requested DN.
     */
    public Rdn getRdn(String type) {
        return getRdn(type, 0);
    }

    /** Get a relative Distinguished Name.
     * @param type type of the DN.
     * @param index index of the DN (in case of multiple occurences).
     * @return the requested DN.
     */
    public Rdn getRdn(String type, int index) {
        return getRdn(this, type, index);
    }

    /** Merge this DN with another provided DN.
     * The result is a new DN resulting from the merge of this DN and the 
     * 
     * @param dn the provided DN.
     * @param override override this DN with provided datas.
     * @return a new DN resulting from the merge.
     */
    public DistinguishedName mergeDN(DistinguishedName dn, boolean override, boolean useEntityEmailField, String entityEmail) {

        // count the number of components of the same type.
        Map componentTypeCount = new HashMap();

        logger.log(Level.INFO, "Trying to merge \n" + dn.toString() + "\n with \n" + this.toString());

        // This list will enclose the resulting list of RDNs.
        List localRdns = new ArrayList();

        // This Map contains some lists of Rdns identified by their type.
        Map providedRdnsMap = new HashMap();

        // init the providedRdnsMap :
        for (ListIterator it = dn.getRdns().listIterator(dn.getRdns().size()); it.hasPrevious(); ) {
            Rdn providedRdn = (Rdn) it.previous();
            if (providedRdnsMap.containsKey(providedRdn.getType())) {
                // add the provided Rdn in the existing list for this type :
                List rdns = (List) providedRdnsMap.get(providedRdn.getType());
                rdns.add(providedRdn);
            } else {
                // create a new list for this type :
                List rdns = new ArrayList();
                rdns.add(providedRdn);
                providedRdnsMap.put(providedRdn.getType(), rdns);
            }
        }

        // convert to a Map of Iterators :
        Map providedRdnIteratorsMap = new HashMap();
        for (Iterator it = providedRdnsMap.keySet().iterator(); it.hasNext(); ) {
            String key = (String) it.next();
            providedRdnIteratorsMap.put(key, ((List) providedRdnsMap.get(key)).iterator());
        }

        // loop on all Rdn and check if they must be replaced :
        for (ListIterator it = getRdns().listIterator(getRdns().size()); it.hasPrevious();) {
            Rdn localRdn = (Rdn) it.previous();
            if (providedRdnIteratorsMap.containsKey(localRdn.getType())
                    && ((Iterator) providedRdnIteratorsMap.get(localRdn.getType())).hasNext()) {
                Rdn providedRdn = (Rdn) ((Iterator) providedRdnIteratorsMap.get(localRdn.getType())).next();
                if (useEntityEmailField && override 
                        && DnComponents.RFC822NAME.equals(localRdn.getType())) {
                    try {
                        localRdns.add(new Rdn(DnComponents.RFC822NAME, entityEmail));
                     } catch (InvalidNameException e) { 
                         // Can't occur.
                     }
                } else if (override) {
                    localRdns.add(providedRdn);
                } else {
                    localRdns.add(localRdn);
                }
            } else {
                localRdns.add(localRdn);
            }
        }

        // loop on all remaining provided components and add them at the end of the dn :
        for (Iterator it = providedRdnIteratorsMap.values().iterator(); it.hasNext(); ) {
            Iterator rdnIterator = (Iterator) it.next();
            while (rdnIterator.hasNext()) {
                Rdn providedRdn = (Rdn) rdnIterator.next();
                if (useEntityEmailField && DnComponents.RFC822NAME.equals(providedRdn.getType())) {
                    try {
                        localRdns.add(new Rdn(DnComponents.RFC822NAME, entityEmail));
                    } catch (InvalidNameException e) {
                        // can't occur.
                    }
                } else {
                    localRdns.add(providedRdn);
                }
            }
        }

        Collections.reverse(localRdns);

        logger.log(Level.INFO, "result :\n" + localRdns);

        // Final step, create a new DN and return it.
        return new DistinguishedName(localRdns);
    }

    /** Get a relative Distinguished Name.
     * @param dn the DN.
     * @param type type of the DN.
     * @return the requested DN.
     */
    public static Rdn getRdn(DistinguishedName dn, String type) {
        return getRdn(dn, type, 0);
    }

    /** Get a relative Distinguished Name.
     * @param dn the DN.
     * @param type type of the DN.
     * @param index index of the DN (in case of multiple occurences).
     * @return the requested DN.
     */
    public static Rdn getRdn(DistinguishedName dn, String type, int index) {

        if (index < 0) {
            return null;
        }

        // list of RDN of the specified type.
        List rdnsOfThisType = new ArrayList();

        // First step, get the list of all Rdn of this type:
        for (Iterator it = dn.getRdns().iterator(); it.hasNext();) {
            Rdn rdn = (Rdn) it.next();
            if (rdn.getType().equalsIgnoreCase(type)) {
                rdnsOfThisType.add(rdn);
            }
        }

        // Second step, return the Rdn at the specified index or null if not exists:
        if (rdnsOfThisType.size() > index) {
            return (Rdn) rdnsOfThisType.get(index);
        } else {
            return null;
        }
    }
}
