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
package org.ejbca.util.query;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import java.util.Collections;

import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * Test of {@link QueryWrapper}
 * 
 * @version $Id$
 */
public class QueryWrapperUnitTest {
    
    private static final Logger log = Logger.getLogger(QueryWrapperUnitTest.class);

    /** Tests without adding any query pieces */
    @Test
    public void empty() {
        log.trace(">empty");
        final QueryWrapper qw = new QueryWrapper();
        assertEquals("Query string should be empty", "", qw.getQueryString());
        assertEquals("Values should be empty", Collections.emptyList(), qw.getValues());
        log.trace("<empty");
    }

    /** Tests with a fixed query, without parameters */
    @Test
    public void withoutQueryParameters() {
        log.trace(">withoutQueryParameters");
        final QueryWrapper qw = new QueryWrapper();
        qw.add("a=1");
        assertEquals("Wrong query string", "a=1", qw.getQueryString());
        assertEquals("Values should be empty", Collections.emptyList(), qw.getValues());
        log.trace("<withoutQueryParameters");
    }

    /** Tests with one query parameter. Note that the <code>?</code> placeholders are replaced with <code>?<i>index</i></code> syntax, which is required by modern application servers. */
    @Test
    public void withQueryParameter() {
        log.trace(">withQueryParameter");
        final QueryWrapper qw = new QueryWrapper();
        final Object obj = new Object();
        qw.add("a=?", obj);
        assertEquals("Wrong query string", "a=?1", qw.getQueryString());
        assertEquals("Wrong number of values", 1, qw.getValues().size());
        assertSame("Wrong parameter value object", obj, qw.getValues().get(0));
        log.trace("<withQueryParameter");
    }

    /** Tests building a query with multiple values, in multiple steps */
    @Test
    public void buildComplexQuery() {
        log.trace(">buildComplexQuery");
        final QueryWrapper qw = new QueryWrapper();
        final Object value1 = new Object();
        final Object value2 = 2;
        final Object value3 = "test";
        qw.add("(a=? AND b=?)", value1, value2);
        qw.add(" OR ");
        qw.add("c=?", value3);
        assertEquals("Wrong query string", "(a=?1 AND b=?2) OR c=?3", qw.getQueryString());
        assertEquals("Wrong number of values", 3, qw.getValues().size());
        assertSame("Wrong parameter value object 1", value1, qw.getValues().get(0));
        assertSame("Wrong parameter value object 1", value2, qw.getValues().get(1));
        assertSame("Wrong parameter value object 1", value3, qw.getValues().get(2));
        log.trace("<buildComplexQuery");
    }
    
    /** Tests with too few values, should throw */
    @Test(expected = IllegalArgumentException.class)
    public void tooFewValues() {
        log.trace(">tooFewValues (will throw)");
        final QueryWrapper qw = new QueryWrapper();
        qw.add("a=?");
    }

    /** Tests with too many values, should throw */
    @Test(expected = IllegalArgumentException.class)
    public void tooManyValues() {
        log.trace(">tooManyValues (will throw)");
        final QueryWrapper qw = new QueryWrapper();
        qw.add("a=", 123);
    }

}
