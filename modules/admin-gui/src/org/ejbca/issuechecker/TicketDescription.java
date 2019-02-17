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

package org.ejbca.issuechecker;

import java.util.Objects;

import org.apache.commons.codec.binary.StringUtils;
import org.ejbca.ui.web.jsf.configuration.WebLanguages;

/**
 * Class containing the description of a ticket.
 *
 * <p>The description should be a short text (typically around 20 words), describing what the problem
 * is and how the ticket can be resolved, or if the ticket is informative only, what the ticket is about.
 * E.g. "EJBCA is not running in production mode, system tests may run on this instance and additional
 * tools for developers are available."
 *
 * <p>This class does not hold the description text directly, instead it contains a language key which
 * can be used to lookup the ticket description in the language file. This makes it possible to load
 * ticket descriptions in the administrator's preferred language dynamically at runtime.
 *
 * @version $Id$
 */
public class TicketDescription {
    private final String languageKey;
    private final String parameter;

    /**
     * Factory method creating a new ticket description from a language resource.
     *
     * @param languageKey the description of the ticket, as a language key.
     * @return a new instance of {@link TicketDescription} class.
     */
    public static TicketDescription fromResource(final String languageKey) {
        return fromResource(languageKey, null);
    }

    /**
     * Factory method creating a new ticket description from a language resource with
     * one argument.
     *
     * @param languageKey the description of the ticket, as a language key.
     * @param parameter a string to insert into the ticket description.
     * @return a new instance of {@link TicketDescription} class.
     */
    public static TicketDescription fromResource(final String languageKey, final String parameter) {
        return new TicketDescription(languageKey, parameter);
    }

    private TicketDescription(final String languageKey, final String parameter) {
        this.languageKey = languageKey;
        this.parameter = parameter;
    }

    /**
     * Get the string representation of this ticket description.
     * @param webLanguages an instance of the {@link WebLanguages} class.
     * @return the ticket description as a string.
     */
    public String toString(final WebLanguages webLanguages) {
        if (parameter == null) {
            return webLanguages.getText(languageKey);
        } else {
            return webLanguages.getText(languageKey, parameter);
        }
    }

    @Override
    public boolean equals(final Object o) {
        if (o == this) {
            return true;
        }
        if (o == null) {
            return false;
        }
        if (!(o instanceof TicketDescription)) {
            return false;
        }
        final TicketDescription ticketDescription = (TicketDescription) o;
        return StringUtils.equals(this.languageKey, ticketDescription.languageKey) &&
               StringUtils.equals(this.parameter, ticketDescription.parameter);
    }

    @Override
    public int hashCode() {
        return Objects.hash(languageKey, parameter);
    }
}
