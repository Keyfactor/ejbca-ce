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
package org.ejbca.util;


/**
 * See {@link #fixXML(String, String, String)}
 * @author lars
 * @version $Id$
 */
public class FixEndOfBrokenXML {
	final private String sXML;
	final private String sTag;
	final private String sTail;
	private int position = 0;
	private int level = 0;
	private FixEndOfBrokenXML( String s, String l, String t ) {
		this.sXML = s;
		this.sTag = l;
		this.sTail = t;
	}
	private void next() {
		final int pLabel = this.sXML.indexOf(this.sTag, this.position);
		if ( pLabel<this.position ) {
			return;
		}
		boolean noHit = true;
		if ( pLabel>2 && this.sXML.substring(pLabel-2, pLabel).equals("</") ) {
			this.position = pLabel-2;
			this.level--;
			noHit = false;
		}
		if ( this.level<0 ) {
			return;
		}
		if ( pLabel>1 && this.sXML.substring(pLabel-1, pLabel).equals("<") ) {
			this.position = pLabel-1;
			this.level++;
			noHit = false;
		}
		if ( noHit ) {
			this.position += this.sTag.length();
			next();
			return;
		}
		final int pEnd = this.sXML.indexOf('>', pLabel);
		if ( pEnd<pLabel+this.sTag.length() ) {
			this.level++;
			return;
		}
		if ( this.sXML.charAt(pEnd-1)=='/' ) {
			this.level--;
		}
		this.position = pEnd+1;
		next();
	}
	private String getFixedString() {
		next();
		if ( this.level<0 ) {
			return null;
		}
		String result = this.sXML.substring(0, this.position);
		for ( int i=0; i<this.level; i++) {
			result += "</"+this.sTag+">";
		}
		result += this.sTail;
		return result;
	}
	/**
	 * Fixes XML with lost characters in the end.
	 * It can fix the XML if less characters than the length of a tail that allways is the same is lost.
	 * @param xml The original broken XML
	 * @param tag the first tag of the tail part that is the same for all data.
	 * @param tail the tail but the the endtag given by ergument 2
	 * @return the fixed XML
	 */
	public static String fixXML(String xml, String tag, String tail) {
		return new FixEndOfBrokenXML(xml, tag, tail).getFixedString();
	}
}
