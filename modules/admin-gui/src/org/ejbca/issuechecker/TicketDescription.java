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

import java.util.ArrayList;
import java.util.List;
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
 * <p>Normally, this class does not hold the description text directly, instead it contains a language key
 * which can be used to lookup the ticket description in the language file. This makes it possible to load
 * ticket descriptions in the administrator's preferred language dynamically at runtime.
 * 
 * <p>However, it is possible to create a ticket description by specifying the ticket description directly.
 * This can be useful during testing, or if an administrator chooses to create their own tickets. 
 *
 * @version $Id$
 */
public class TicketDescription {
    private String languageKey;
    private List<String> parameters = new ArrayList<>();
    private String text;

    /**
     * Factory method creating a new ticket description from a language resource.
     *
     * @param languageKey the description of the ticket, as a language key.
     * @return a new instance of {@link TicketDescription} class.
     */
    public static TicketDescription fromResource(final String languageKey) {
        final TicketDescription ticketDescription = new TicketDescription();
        ticketDescription.languageKey = languageKey;
        return ticketDescription;
    }

    /**
     * Factory method creating a new ticket description from a language resource with
     * one parameter.
     *
     * @param languageKey the description of the ticket, as a language key.
     * @param parameter a string to insert into the ticket description.
     * @return a new instance of {@link TicketDescription} class.
     */
    public static TicketDescription fromResource(final String languageKey, final String parameter) {
        final TicketDescription ticketDescription = new TicketDescription();
        ticketDescription.languageKey = languageKey;
        ticketDescription.parameters.add(parameter);
        return ticketDescription;
    }

    /**
     * Factory method creating a new ticket description from a language resource with
     * two parameters.
     *
     * @param languageKey the description of the ticket, as a language key.
     * @param parameter1 the first string to insert into the ticket description.
     * @param parameter2 the second string to insert into the ticket description.
     * @return a new instance of {@link TicketDescription} class.
     */
    public static TicketDescription fromResource(final String languageKey, final String parameter1, final String parameter2) {
        final TicketDescription ticketDescription = new TicketDescription();
        ticketDescription.languageKey = languageKey;
        ticketDescription.parameters.add(parameter1);
        ticketDescription.parameters.add(parameter2);
        return ticketDescription;
    }

    public static TicketDescription fromStringLiteral(final String text) {
        final TicketDescription ticketDescription = new TicketDescription();
        ticketDescription.text = text;
        return ticketDescription;
    }

    /**
     * Get the string representation of this ticket description.
     *
     * @param webLanguages an instance of the {@link WebLanguages} class.
     * @return the ticket description as a string.
     */
    public String toString(final WebLanguages webLanguages) {
        if (text != null) {
            return text;
        } else if (parameters.size() == 1) {
            return webLanguages.getText(languageKey, parameters.get(0));
        } else if (parameters.size() == 2) {
            return webLanguages.getText(languageKey, parameters.get(0), parameters.get(1));
        } else {
            return webLanguages.getText(languageKey);
        }
    }

    @Override
    public String toString() {
        if (text != null) {
            return text;
        }
        if (parameters.size() == 0) {
            return languageKey;
        }
        return String.format("(%s, %s)", languageKey, String.join(", ", parameters));
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
               this.parameters.equals(ticketDescription.parameters) &&
               StringUtils.equals(this.text, ticketDescription.text); 
    }

    @Override
    public int hashCode() {
        return Objects.hash(languageKey, parameters, text);
    }
}
