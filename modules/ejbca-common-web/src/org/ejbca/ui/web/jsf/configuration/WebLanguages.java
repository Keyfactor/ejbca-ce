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

package org.ejbca.ui.web.jsf.configuration;

import java.util.List;

import org.ejbca.ui.web.configuration.WebLanguage;

/**
 * An class interpreting the language properties files. It contains a method {@link WebLanguages#getText(String, Object...)}
 * that returns the presented text in the users preferred language.
 *
 * @version $Id$
 */
public interface WebLanguages {

    /**
     * Lookup up a language string in the users preferred language.
     *
     * @param template a language key, identifying a language string in the language file.
     * @param params optional parameters to insert into the language string
     * @return a text in the users preferred language.
     */
    String getText(String languageKey, Object... params);

    /**
     *  Returns an array of strings representing all available languages.
     *  @return an array of strings, representing all available languages.
     */
    String[] getAvailableLanguages();

    /**
     *  Returns a list of available languages for EJBCA.
     *  @param a list of {@link WebLanguages} objects.
     */
    List<WebLanguage> getWebLanguages();
}