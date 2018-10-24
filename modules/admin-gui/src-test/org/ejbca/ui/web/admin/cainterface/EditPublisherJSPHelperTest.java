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
package org.ejbca.ui.web.admin.cainterface;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Test for EditPublisherJSPHelper
 * @see EditPublisherJSPHelper
 * @version $Id: EditPublisherJSPHelperTest.java 29652 2018-08-15 12:05:16Z anatom $
 */
public class EditPublisherJSPHelperTest {

    EditPublisherJSPHelper helper = new EditPublisherJSPHelper();


    @Test
    public void convertMultiPublishersStringToData() throws Exception {
        String input = "Apple\nOrange\n\nKiwi\nBanan\nAvocado";
        List<TreeSet<Integer>> result = helper.convertMultiPublishersStringToData(getNameToIdMap(), input);
        assertEquals("Sould contain 2 lists", 2, result.size());
        assertEquals("First set contain 2 elements", 2, result.get(0).size());
        assertEquals("Second set contain 3 elements", 3, result.get(1).size());
        assertEquals("First element of first group should be Apple(1)", Integer.valueOf(1), result.get(0).first());
        assertEquals("First element of first group should be Banan(2)", Integer.valueOf(2), result.get(1).first());
    }

    @Test(expected = PublisherDoesntExistsException.class)
    public void convertMultiPublishersStringToDataNotExistinPublisher() throws Exception {
        String input = "Apple\nOrange\n\nKiwi\nblablalba\nAvocado";
        List<TreeSet<Integer>> result = helper.convertMultiPublishersStringToData(getNameToIdMap(), input);
    }

    @Test(expected = PublisherExistsException.class)
    public void convertMultiPublishersStringToDataDoublicatePublisher() throws Exception {
        String input = "Apple\nOrange\n\nKiwi\nApple\nAvocado";
        List<TreeSet<Integer>> result = helper.convertMultiPublishersStringToData(getNameToIdMap(), input);
    }
    @Test
    public void convertMultiPublishersStringToDataNewLinesAndSpaces() throws Exception {
        String input = "Apple \n Orange\n\n\n\nKiwi\nBanan\nAvocado\n\n\n\n\n";
        List<TreeSet<Integer>> result = helper.convertMultiPublishersStringToData(getNameToIdMap(), input);
        assertEquals("Sould contain 2 lists", 2, result.size());
        assertEquals("First set contain 2 elements", 2, result.get(0).size());
        assertEquals("Second set contain 3 elements", 3, result.get(1).size());
        assertEquals("First element of first group should be Apple(1)", Integer.valueOf(1), result.get(0).first());
        assertEquals("First element of first group should be Banan(2)", Integer.valueOf(2), result.get(1).first());
    }

    @Test
    public void convertMultiPublishersDataToString() throws Exception {
        ArrayList<TreeSet<Integer>> data = new ArrayList<>();
        TreeSet<Integer> tree = new TreeSet<>();
        tree.add(1);
        tree.add(5);

        data.add(tree);
        tree = new TreeSet<>();
        tree.add(4);
        tree.add(3);
        data.add(tree);

        String result = helper.convertMultiPublishersDataToString(getIdToNameMap(), data);
        String expected = "Apple\nPomelo\n\nKiwi\nOrange";
        assertEquals("Should return multi publishers string", expected, result);
    }

    private Map<Integer, String> getIdToNameMap() {
        Map<Integer, String> publisherNameToIdMap = new HashMap<>();
        publisherNameToIdMap.put(1, "Apple");
        publisherNameToIdMap.put(2, "Banan");
        publisherNameToIdMap.put(3, "Kiwi");
        publisherNameToIdMap.put(4, "Orange");
        publisherNameToIdMap.put(5, "Pomelo");
        publisherNameToIdMap.put(6, "Grape");
        publisherNameToIdMap.put(7, "Avocado");
        return publisherNameToIdMap;
    }
    private static Map<String, Integer> getNameToIdMap() {
        Map<String, Integer> publisherNameToIdMap = new HashMap<>();
        publisherNameToIdMap.put("Apple", 1);
        publisherNameToIdMap.put("Banan", 2);
        publisherNameToIdMap.put("Kiwi", 3);
        publisherNameToIdMap.put("Orange", 4);
        publisherNameToIdMap.put("Greip", 5);
        publisherNameToIdMap.put("Grape", 6);
        publisherNameToIdMap.put("Avocado", 7);
        return publisherNameToIdMap;
    }
}