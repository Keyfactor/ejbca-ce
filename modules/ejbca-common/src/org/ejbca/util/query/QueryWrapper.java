package org.ejbca.util.query;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;




/**
 * This class wrap queryString and value for SQL prepared statements
 * 
 * @version $Id$
 */
public class QueryWrapper{
    
    private final StringBuilder queryString = new StringBuilder();            
    private final List <Object> values = new ArrayList<>();   
    
    private static final Pattern SQL_ARGUMENT = Pattern.compile("[?]");
    
    public String getQueryString() {
        return queryString.toString();
    }
    public List<Object> getValues() {
        return values;
    }
    
    /**
     * Adds a piece of a query string, with <code>?</code> placeholders, and their corresponding values.
     * Note that only ? placeholders are supported, not ?1 ?2 etc. or other syntaxes.
     *
     * @param str Query string piece. Should have exactly one ? placeholder per value.
     * @param objs Values that correspond to the ? placeholders.
     * @throws IllegalArgumentException if there are different numbers of values and ? placeholders. 
     */
    public void add(String str, Object... objs) {
        Matcher m = SQL_ARGUMENT.matcher(str);
        int pos = 0;
        int i = values.size();
        while (m.find()) {
            queryString.append(str, pos, m.start());
            pos = m.end();
            queryString.append("?"+ ++i);          
        }
        queryString.append(str, pos, str.length());
        if (i - values.size() != objs.length) {
            throw new IllegalArgumentException("Number of ? placeholders and values do not match in query, was " + (i - values.size()) + " expected " + objs.length + ". Query '" + str + "'");
        }
        Collections.addAll(values, objs);
    }

}
