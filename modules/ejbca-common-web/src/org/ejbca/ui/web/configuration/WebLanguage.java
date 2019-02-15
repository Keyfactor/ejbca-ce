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
package org.ejbca.ui.web.configuration;

/*
 * DTO class for holding information and properties about one language
 *
 * @version $Id: CacheClearException.java 22945 2016-03-09 13:32:20Z mikekushner $
 */
public class WebLanguage {

    private int id;
    private String englishName;
    private String nativeName;
    private String abbreviation;

    public WebLanguage(final int id, final String englishName, final String nativeName, final String abbreviation) {
        this.id = id;
        this.englishName = englishName;
        this.nativeName = nativeName;
        this.abbreviation = abbreviation;
    }

    public int getId() {
        return id;
    }
    public void setId(final int id) {
        this.id = id;
    }
    public String getEnglishName() {
        return englishName;
    }
    public void setEnglishName(final String englishName) {
        this.englishName = englishName;
    }
    public String getNativeName() {
        return nativeName;
    }
    public void setNativeName(final String nativeName) {
        this.nativeName = nativeName;
    }
    public String getAbbreviation() {
        return abbreviation;
    }
    public void setAbbreviation(final String abbreviation) {
        this.abbreviation = abbreviation;
    }

    @Override
    public String toString() {
        return englishName + " - " + nativeName + " [" + abbreviation + "]";
    }

}
