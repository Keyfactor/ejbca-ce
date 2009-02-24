/*
 * ====================================================================
 * Copyright (c) 1995-1999 Purple Technology, Inc. All rights
 * reserved.
 *
 * PLAIN LANGUAGE LICENSE: Do whatever you like with this code, free
 * of charge, just give credit where credit is due. If you improve it,
 * please send your improvements to alex@purpletech.com. Check
 * http://www.purpletech.com/code/ for the latest version and news.
 *
 * LEGAL LANGUAGE LICENSE: Redistribution and use in source and binary
 * forms, with or without modification, are permitted provided that
 * the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. The names of the authors and the names "Purple Technology,"
 * "Purple Server" and "Purple Chat" must not be used to endorse or
 * promote products derived from this software without prior written
 * permission. For written permission, please contact
 * server@purpletech.com.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND PURPLE TECHNOLOGY ``AS
 * IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * AUTHORS OR PURPLE TECHNOLOGY BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ====================================================================
 *
 **/
package org.ejbca.util;

import java.util.HashMap;
import java.util.Map;

public class HTMLTools {
//	 see http://hotwired.lycos.com/webmonkey/reference/special_characters/
    static Object[][] entities = {
       // {"#39", new Integer(39)},       // ' - apostrophe
        {"quot", new Integer(34)},      // " - double-quote
        {"amp", new Integer(38)},       // & - ampersand
        {"lt", new Integer(60)},        // < - less-than
        {"gt", new Integer(62)},        // > - greater-than
        {"nbsp", new Integer(160)},     // non-breaking space
        {"copy", new Integer(169)},     // © - copyright
        {"reg", new Integer(174)},      // ® - registered trademark
        {"Agrave", new Integer(192)},   // À - uppercase A, grave accent
        {"Aacute", new Integer(193)},   // Á - uppercase A, acute accent
        {"Acirc", new Integer(194)},    // Â - uppercase A, circumflex accent
        {"Atilde", new Integer(195)},   // Ã - uppercase A, tilde
        {"Auml", new Integer(196)},     // Ä - uppercase A, umlaut
        {"Aring", new Integer(197)},    // Å - uppercase A, ring
        {"AElig", new Integer(198)},    // Æ - uppercase AE
        {"Ccedil", new Integer(199)},   // Ç - uppercase C, cedilla
        {"Egrave", new Integer(200)},   // È - uppercase E, grave accent
        {"Eacute", new Integer(201)},   // É - uppercase E, acute accent
        {"Ecirc", new Integer(202)},    // Ê - uppercase E, circumflex accent
        {"Euml", new Integer(203)},     // Ë - uppercase E, umlaut
        {"Igrave", new Integer(204)},   // Ì - uppercase I, grave accent
        {"Iacute", new Integer(205)},   // Í - uppercase I, acute accent
        {"Icirc", new Integer(206)},    // Î - uppercase I, circumflex accent
        {"Iuml", new Integer(207)},     // Ï - uppercase I, umlaut
        {"ETH", new Integer(208)},      // Ð - uppercase Eth, Icelandic
        {"Ntilde", new Integer(209)},   // Ñ - uppercase N, tilde
        {"Ograve", new Integer(210)},   // Ò - uppercase O, grave accent
        {"Oacute", new Integer(211)},   // Ó - uppercase O, acute accent
        {"Ocirc", new Integer(212)},    // Ô - uppercase O, circumflex accent
        {"Otilde", new Integer(213)},   // Õ - uppercase O, tilde
        {"Ouml", new Integer(214)},     // Ö - uppercase O, umlaut
        {"Oslash", new Integer(216)},   // Ø - uppercase O, slash
        {"Ugrave", new Integer(217)},   // Ù - uppercase U, grave accent
        {"Uacute", new Integer(218)},   // Ú - uppercase U, acute accent
        {"Ucirc", new Integer(219)},    // Û - uppercase U, circumflex accent
        {"Uuml", new Integer(220)},     // Ü - uppercase U, umlaut
        {"Yacute", new Integer(221)},   // Ý - uppercase Y, acute accent
        {"THORN", new Integer(222)},    // Þ - uppercase THORN, Icelandic
        {"szlig", new Integer(223)},    // ß - lowercase sharps, German
        {"agrave", new Integer(224)},   // à - lowercase a, grave accent
        {"aacute", new Integer(225)},   // á - lowercase a, acute accent
        {"acirc", new Integer(226)},    // â - lowercase a, circumflex accent
        {"atilde", new Integer(227)},   // ã - lowercase a, tilde
        {"auml", new Integer(228)},     // ä - lowercase a, umlaut
        {"aring", new Integer(229)},    // å - lowercase a, ring
        {"aelig", new Integer(230)},    // æ - lowercase ae
        {"ccedil", new Integer(231)},   // ç - lowercase c, cedilla
        {"egrave", new Integer(232)},   // è - lowercase e, grave accent
        {"eacute", new Integer(233)},   // é - lowercase e, acute accent
        {"ecirc", new Integer(234)},    // ê - lowercase e, circumflex accent
        {"euml", new Integer(235)},     // ë - lowercase e, umlaut
        {"igrave", new Integer(236)},   // ì - lowercase i, grave accent
        {"iacute", new Integer(237)},   // í - lowercase i, acute accent
        {"icirc", new Integer(238)},    // î - lowercase i, circumflex accent
        {"iuml", new Integer(239)},     // ï - lowercase i, umlaut
        {"igrave", new Integer(236)},   // ì - lowercase i, grave accent
        {"iacute", new Integer(237)},   // í - lowercase i, acute accent
        {"icirc", new Integer(238)},    // î - lowercase i, circumflex accent
        {"iuml", new Integer(239)},     // ï - lowercase i, umlaut
        {"eth", new Integer(240)},      // ð - lowercase eth, Icelandic
        {"ntilde", new Integer(241)},   // ñ - lowercase n, tilde
        {"ograve", new Integer(242)},   // ò - lowercase o, grave accent
        {"oacute", new Integer(243)},   // ó - lowercase o, acute accent
        {"ocirc", new Integer(244)},    // ô - lowercase o, circumflex accent
        {"otilde", new Integer(245)},   // õ - lowercase o, tilde
        {"ouml", new Integer(246)},     // ö - lowercase o, umlaut
        {"oslash", new Integer(248)},   // ø - lowercase o, slash
        {"ugrave", new Integer(249)},   // ù - lowercase u, grave accent
        {"uacute", new Integer(250)},   // ú - lowercase u, acute accent
        {"ucirc", new Integer(251)},    // û - lowercase u, circumflex accent
        {"uuml", new Integer(252)},     // ü - lowercase u, umlaut
        {"yacute", new Integer(253)},   // ý - lowercase y, acute accent
        {"thorn", new Integer(254)},    // þ - lowercase thorn, Icelandic
        {"yuml", new Integer(255)},     // ÿ - lowercase y, umlaut
        {"euro", new Integer(8364)},    // Euro symbol
    };
    static Map e2i = new HashMap();
    static Map i2e = new HashMap();
    static {
        for (int i=0; i<entities.length; ++i) {
            e2i.put(entities[i][0], entities[i][1]);
            i2e.put(entities[i][1], entities[i][0]);
        }
    }

    /**
     * Turns funky characters into HTML entity equivalents<p>
     * e.g. <tt>"bread" & "butter"</tt> => <tt>&amp;quot;bread&amp;quot; &amp;amp; &amp;quot;butter&amp;quot;</tt>.
     * Update: supports nearly all HTML entities, including funky accents. See the source code for more detail.
     * @see #htmlunescape(String)
     **/
    public static String htmlescape(String s1)
    {
    	if (s1 == null) {
    		return null;
    	}
        StringBuffer buf = new StringBuffer();
        int i;
        for (i=0; i<s1.length(); ++i) {
            char ch = s1.charAt(i);
            String entity = (String)i2e.get( new Integer(ch) );
            if (entity == null) {
                if ((ch) > 128) {
                    buf.append("&#" + ((int)ch) + ";");
                }
                else {
                    buf.append(ch);
                }
            }
            else {
                buf.append("&" + entity + ";");
            }
        }
        return buf.toString();
    }

    /**
     * Given a string containing entity escapes, returns a string
     * containing the actual Unicode characters corresponding to the
     * escapes.
     *
     * Note: nasty bug fixed by Helge Tesgaard (and, in parallel, by
     * Alex, but Helge deserves major props for emailing me the fix).
     * 15-Feb-2002 Another bug fixed by Sean Brown <sean@boohai.com>
     *
     * @see #htmlescape(String)
     **/
    public static String htmlunescape(String s1) {
    	if (s1 == null) {
    		return null;
    	}
        StringBuffer buf = new StringBuffer();
        int i;
        for (i=0; i<s1.length(); ++i) {
            char ch = s1.charAt(i);
            if (ch == '&') {
                int semi = s1.indexOf(';', i+1);
                if (semi == -1) {
                    buf.append(ch);
                    continue;
                }
                String entity = s1.substring(i+1, semi);
                Integer iso;
                if (entity.charAt(0) == '#') {
                    iso = new Integer(entity.substring(1));
                }
                else {
                    iso = (Integer)e2i.get(entity);
                }
                if (iso == null) {
                    buf.append("&" + entity + ";");
                }
                else {
                    buf.append((char)(iso.intValue()));
                }
                i = semi;
            }
            else {
                buf.append(ch);
            }
        }
        return buf.toString();
    }
    
    public static String javascriptEscape(String str) {
    	String ret = str;
    	// In javascript the apostrof will destroy strings and cause the javascript to break
    	ret = ret.replaceAll("'", "\\\\'");
    	return ret;
    }
}
