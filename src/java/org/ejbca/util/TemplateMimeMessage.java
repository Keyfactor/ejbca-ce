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

package org.ejbca.util;

import javax.mail.internet.MimeMessage;
import javax.mail.Session;
import javax.mail.MessagingException;
import java.util.HashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * This is an extremely simple template message to be used to interpolate some values that exists
 * in the content written as ${identifier}.
 * <p />
 * It is nowhere as powerful as Jakarta Velocity with its VelocityEmail but it's not intended to be.
 * <p />
 * Only subject and content data is interpolated.
 * <code>
 *  HashMap params = new HashMap();
 *  params.put("username", "John Doe");
 *
 *  Session session = (Session)ctx.lookup("java:comp/env/mail/MyMail");
 *  TemplateMimeMessage msg = new TemplateMimeMessage(params, session);
 *  msg.setSubject("${username}, here is a message for your");
 *  msg.setContent("Hello ${username}", "text/plain");
 *  ...
 *
 * </code>
 * 
 * @version $Id: TemplateMimeMessage.java,v 1.2 2006-02-08 07:31:48 anatom Exp $
 */
public class TemplateMimeMessage extends MimeMessage {

    /** the map of Pattern/String objects to interpolate in the content */
    private HashMap patterns;

    /** regexp pattern to match ${identifier} patterns */
    private final static Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}");

    /**
     * Construct a new TemplateMimeMessage which content is to be interpolated
     * For instance specifying a map entry as ('welcome', 'Hello World') and having a content
     * with '${welcome}' will have it to be interpolated as 'Hello World'
     *
     * @param patterns the map of String/String objects
     * @param session the mail session to use.
     */
    public TemplateMimeMessage(HashMap patterns, Session session) {
        super(session);
        this.patterns = patterns;
    }

    public void setSubject(String s) throws MessagingException {
        setSubject(s, null);
    }

    public void setSubject(String s, String s1) throws MessagingException {
        String interpolatedContent = interpolate(s);
        super.setSubject(interpolatedContent, s1);
    }

    public void setContent(Object content, String s) throws MessagingException {
        // template message supports only String message
        if(!(content instanceof String)) {
            throw new MessagingException("Requires a String content, was given object of type " + content.getClass().toString());
        }
        String interpolatedContent = interpolate((String)content);
        super.setContent(interpolatedContent, s);
    }


    /**
     * Interpolate the patterns that exists on the input on the form '${pattern}'.
     * @param input the input content to be interpolated
     * @return the interpolated content
     */
    protected String interpolate(String input) {
        final Matcher m = PATTERN.matcher(input);
        final StringBuffer sb = new StringBuffer(input.length());
        while (m.find()) {
            // when the pattern is ${identifier}, group 0 is 'identifier'
            String key = m.group(1);
            String value = (String)patterns.get(key);
            // if the pattern does exists, replace it by its value
            // otherwise keep the pattern ( it is group(0) )
            if (value != null) {
                m.appendReplacement(sb, value);
            } else {
                // I'm doing this to avoid the backreference problem as there will be a $
                // if I replace directly with the group 0 (which is also a pattern)
                m.appendReplacement(sb, "");
                String unknown = m.group(0);
                sb.append(unknown);
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

}
