/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.ui.components;

import java.util.ArrayList;
import java.util.List;

import org.cesecore.ui.DynamicJsfComponent;
import org.cesecore.ui.JsfComponentType;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

/**
 * Implementation of a radio group which renders a set of radio buttons. The user
 * can click one of these buttons to select it, and only one button can be selected
 * at a time.
 * @version $Id$
 */
public class JsfRadioGroup extends DynamicJsfComponent {
    private List<String> possibleChoices = new ArrayList<String>();
    private String selectedChoice;

    @SuppressWarnings("unchecked")
    @Override
    public JSONObject toJson() {
        final JSONObject jsonObject = new JSONObject();
        final JSONArray jsonArray = new JSONArray();
        jsonArray.addAll(possibleChoices);
        jsonObject.put("type", "radioGroup");
        if (label != null) {
            jsonObject.put("label", label);
        }
        jsonObject.put("possibleChoices", jsonArray);
        if (selectedChoice != null) {
            jsonObject.put("selectedChoice", selectedChoice);
        }
        return jsonObject;
    }

    @Override
    public String getFacelet() {
        return "";
    }

    @Override
    public JsfComponentType getType() {
        return JsfComponentType.RadioGroup;
    }

    /**
     * Get the choice selected by the user or null if there are no choices
     * to choose from.
     * @return the selected choice
     */
    public String getSelectedChoice() {
        return selectedChoice;
    }

    /**
     * Set the choice selected by the user.
     * @param selectedChoice the new choice which has been selected
     */
    public void setSelectedChoice(final String selectedChoice) {
        this.selectedChoice = selectedChoice;
    }

    /**
     * Get a list of all possible choices or an empty list if there
     * are no choices possible.
     * @return all possible choices in this radio group
     */
    public List<String> getPossibleChoices() {
        return possibleChoices;
    }
}
