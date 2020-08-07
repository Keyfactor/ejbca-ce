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
package org.ejbca.util.dn;

import org.apache.log4j.Logger;
import org.cesecore.certificates.util.DnComponents;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

/** This class aims to be DN representation.
 * It offers facilities to merge two DN.
 * 
 * This class is ripe for rewriting. It is overly complex, as well as limited. 
 * See https://jira.primekey.se/browse/ECA-9108
 * 
 * @version $Id$
 */
public class DistinguishedName extends LdapName {

    private static final long serialVersionUID = -66612792695581203L;
    private static final Logger log = Logger.getLogger(DistinguishedName.class);

    /** Public constructor.
     * Note that this constructor (from LdapName) makes things reverted...
     * If you pass in an array like:
     * [OU=Unit7, C=SE, O=Org1, OU=Unit3, OU=Unit2, OU=Unit1, CN=User Usersson]
     * the .toString() output will be:
     * CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE,OU=Unit7
     * which is on the contrary to the string constructor below.
     * This follows by the javadoc of: https://docs.oracle.com/javase/8/docs/api/index.html
     * 
     * @param rdns list of Rdn's, for example an ArrayList of 'new Rdn("CN", "User Usersson")'
     */
    public DistinguishedName(List<Rdn> rdns) {
        super(rdns);
    }

    /** Public constructor.
     * If you pass in a String like:
     * CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE
     * the .toString() output will be:
     * CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE
     * 
     * @param name DN string for example 'CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE'
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
     * The result is a new DN resulting from the merge of this DN and the provided DN
     * 
     * @param dn the provided DN.
     * @param override override this DN with provided values in the provided DN.
     * @param dnMap values that must be inserted in the DN.
     * @return a new DN resulting from the merge.
     */
    public DistinguishedName mergeDN(final DistinguishedName dn, final boolean override, final Map<String,String> dnMap) {

        boolean useEntityEmailField = (dnMap == null ? false : (dnMap.size() > 0));

        if (log.isDebugEnabled()) {
            log.debug("Trying to merge \n'" + this.toString() + "'\n with \n'" + dn.toString() + "': useEntityEmailField=" + useEntityEmailField);
        }

        // This list will enclose the resulting list of RDNs.
        final List<Rdn> localRdns = new ArrayList<Rdn>();

        // This Map contains some lists of Rdns identified by their type, we need it ordered, hence LinkedHashMap.
        final Map<String, List<Rdn>> providedRdnsMap = new LinkedHashMap<String, List<Rdn>>();

        // init the providedRdnsMap :
        for (Iterator<Rdn> it = dn.getRdns().iterator(); it.hasNext(); ) {
            final Rdn providedRdn = (Rdn) it.next();
            if (providedRdnsMap.containsKey(providedRdn.getType())) {
                // add the provided Rdn in the existing list for this type :
                final List<Rdn> rdns = (List<Rdn>) providedRdnsMap.get(providedRdn.getType());
                rdns.add(providedRdn);
            } else {
                // create a new list for this type :
                final List<Rdn> rdns = new ArrayList<Rdn>();
                rdns.add(providedRdn);
                providedRdnsMap.put(providedRdn.getType(), rdns);
            }
        }

        // convert to a Map of Iterators :
        final Map<String,ListIterator<Rdn>> providedRdnIteratorsMap = new LinkedHashMap<String,ListIterator<Rdn>>();
        for (Iterator<String> it = providedRdnsMap.keySet().iterator(); it.hasNext(); ) {
            final String key = (String) it.next();
            final List<Rdn> list = providedRdnsMap.get(key);
            providedRdnIteratorsMap.put(key, list.listIterator(list.size())); // start iterating backwards, as everywhere else...
        }

        // loop on all Rdn (of this class) and check if they must be replaced :
        for (ListIterator<Rdn> it = getRdns().listIterator(getRdns().size()); it.hasPrevious();) {
            final Rdn localRdn = (Rdn) it.previous();
            final ListIterator<Rdn> providedRdnIterator = providedRdnIteratorsMap.get(localRdn.getType());
            if (providedRdnIterator != null
                    && providedRdnIterator.hasPrevious()) {
                final Rdn providedRdn = (Rdn) (providedRdnIteratorsMap.get(localRdn.getType())).previous();
                if (override) {
                    localRdns.add(providedRdn);
                } else {
                    localRdns.add(localRdn);
                }
            } else {
                if (useEntityEmailField && override) {
                    boolean found = false;
                    for (Iterator<String> dnIt = dnMap.keySet().iterator(); dnIt.hasNext();) {
                        final String key = (String) dnIt.next();
                        if (translateComponentName(key).equalsIgnoreCase(localRdn.getType())) {
                            found = true;
                        }
                    }
                    if (found) {
                        final String value = (String) dnMap.get(localRdn.getType().toUpperCase());
                        try {
                            localRdns.add(new Rdn(translateComponentName(localRdn.getType().toUpperCase()), value));
                        } catch (InvalidNameException e) {
                            // Can't occur.
                        }
                    } else {
                        localRdns.add(localRdn);
                    }
                } else {
                    localRdns.add(localRdn);
                }
            }
        }

        // loop on all remaining provided components and add them at the end of the dn. 
        Collection<ListIterator<Rdn>> values = providedRdnIteratorsMap.values();
        List<Rdn> toAdd = new ArrayList<Rdn>();
        for (Iterator<ListIterator<Rdn>> it = values.iterator(); it.hasNext(); ) {
            final ListIterator<Rdn> rdnIterator = it.next();
            List<Rdn> addOnRdnsOfType = new ArrayList<Rdn>();
            while (rdnIterator.hasPrevious()) {
                final Rdn providedRdn = (Rdn) rdnIterator.previous();
                // Now these, who may be a row of OUs to add, also gets in the reverse order
                addOnRdnsOfType.add(providedRdn);
            }
            Collections.reverse(addOnRdnsOfType);
            toAdd.addAll(addOnRdnsOfType);
        }
        // the crux is, we need to add them in reverse now, as we want to "merge" them as the input was
        Collections.reverse(toAdd);
        localRdns.addAll(toAdd);

        // Add entity data if necessary
        if (useEntityEmailField) {
            for (Iterator<String> it = dnMap.keySet().iterator(); it.hasNext();) {
                boolean found = false;
                final String compName = (String) it.next();
                for (Iterator<Rdn> rdnIt = localRdns.iterator(); rdnIt.hasNext();) {
                    final Rdn rdn = (Rdn) rdnIt.next();
                    if (translateComponentName(compName).equalsIgnoreCase(rdn.getType())) {
                        found = true;
                    }
                }
                if (!found) {
                    final String value = (String) dnMap.get(compName);
                    if (value != null) {
                        try {
                            localRdns.add(new Rdn(translateComponentName(compName), value));
                        } catch (InvalidNameException e) { } // never occurs                    	
                    }
                }
            }
        }

        // Final step, create a new DN and return it.
        // Reverse to return it as it was passed in, this is needed because the constructor to LdapDN (super below) sets things in 
        // reverse order between the string and List<Rdn> constructors
        Collections.reverse(localRdns);
        final DistinguishedName ret = new DistinguishedName(localRdns);
        if (log.isDebugEnabled()) {
            log.debug("result :\n" + ret.toString());
        }
        return ret;
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
     * @param index index of the DN (in case of multiple occurrences).
     * @return the requested DN.
     */
    public static Rdn getRdn(DistinguishedName dn, String type, int index) {

        if (index < 0) {
            return null;
        }

        // list of RDN of the specified type.
        final List<Rdn> rdnsOfThisType = new ArrayList<Rdn>();

        // First step, get the list of all Rdn of this type:
        for (Iterator<Rdn> it = dn.getRdns().iterator(); it.hasNext();) {
            final Rdn rdn = (Rdn) it.next();
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

    /** Translate component name (ejbca name -> x509).
     * @param name to translate.
     * @return translated name.
     */
    public String translateComponentName(String name) {
        if (DnComponents.DNEMAILADDRESS.equals(name)) {
            return "E";
        }
        return name;
    }
}
