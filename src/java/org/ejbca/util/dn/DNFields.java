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

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * DN field handling. Features to take care of fields with empty values.
 * @author primelars
 * @version $Id$
 *
 */
class DNFields {
    private static class Field {
        final String key;
        final String value;
        Field(String s) throws Exception {
            final int pos = s.indexOf('=');
            if ( pos<1 ) {
                throw new Exception("DN field definition is missing the '='");
            }
            this.key = s.substring(0,pos);
            if ( pos+1>=s.length() ) {
                this.value = null;
            } else {
                this.value = s.substring(pos+1);
            }
        }
        /* (non-Javadoc)
         * @see java.lang.Object#toString()
         */
        @Override
        public String toString() {
            return this.key+'='+(this.value!=null ? this.value : "");
        }
        /* (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        @Override
        public boolean equals( Object o ) {
            return o!=null && o instanceof Field && ((Field)o).value!=null && ((Field)o).key.equals(this.key);
        }
    }
    private static void addIfNotEmptyOrNotLast(List<Field> input, List<Field> output) {
        final Field next = input.remove(0);
        // input.contains is true if it is at least one field in the remaining fields (input) with one key that is not null.
        if ( next.value!=null || input.contains(next) ) {
            output.add(next);
        }
        if ( input.size()>0 ) {
            // examine the rest
            addIfNotEmptyOrNotLast(input, output);
        }
    }
    private static boolean isLastBackSlash( String s ) {
        if ( s.length()<1 || s.charAt(s.length()-1)!='\\' ) {
            return false;
        }
        // we now know that last char is '\\'. But if there is an even number of them in a row the last is just a character not an escape for ','
        if ( s.length()<2 || s.charAt(s.length()-2)!='\\' ) {
            return true;// no '\\' after the first
        }
        // since we now have examined 2 chars we can remove this and see if an even number remians.
        return isLastBackSlash(s.substring(0, s.length()-2));
    }
    private static List<Field> getLinkedList( String sDN ) throws Exception {
        final LinkedList<Field> input = new LinkedList<Field>();
        final String sArray[] = sDN.split(",");
        String s="";
        for ( int i=0; i<sArray.length; i++) {
            final String sThis = sArray[i];
            s+=sThis;
            if ( isLastBackSlash(sThis) ) {
                s += ',';
            } else {
                input.add(new Field(s));
                s="";
            }
        }
        return input;
    }
    final private List<Field> list;
    private DNFields( List<Field> l ) {
        this.list = l;
    }
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        final Iterator<Field> i = this.list.iterator();
        String sReturn = null;
        while( i.hasNext() ) {
            if ( sReturn==null ) {
                sReturn = "";
            } else {
                sReturn +=',';
            }
            final Field next = i.next();
            sReturn += next.key+'='+(next.value!=null ? next.value : "");
        }
        return sReturn;
    }
    /**
     * See see {@link DNFieldsUtil#removeTrailingEmpties(String)}
     * @param sDN
     * @return reduced DN
     * @throws Exception if DN has not a valid syntax
     */
    static DNFields removeTrailingEmpties( String sDN ) throws Exception {
        final List<Field> list = new LinkedList<Field>();
        addIfNotEmptyOrNotLast( getLinkedList(sDN), list );
        return new DNFields(list);
    }
    /**
     * see {@link DNFieldsUtil#removeAllEmpties(String)}
     * @param sDN DN string that may contain empties.
     * @return reduced DN
     * @throws Exception if DN has not a valid syntax
     */
    static DNFields removeAllEmpties(String sDN) throws Exception {
        final List<Field> l = new LinkedList<Field>();
        final Iterator<Field> i = getLinkedList(sDN).iterator();
        while( i.hasNext() ) {
            final Field next = i.next();
            if ( next.value!=null ) {
                l.add(next);
            }
        }
        return new DNFields(l);
    }
}
