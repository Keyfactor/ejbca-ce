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
package org.ejbca.ui.web.admin.ca;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.faces.FacesException;
import javax.faces.context.FacesContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificate.ca.its.region.CircularRegion;
import org.cesecore.certificate.ca.its.region.IdentifiedRegionCountryRegions;
import org.cesecore.certificate.ca.its.region.IdentifiedRegions;
import org.cesecore.certificate.ca.its.region.ItsGeographicElement;
import org.cesecore.certificate.ca.its.region.ItsGeographicRegion;
import org.cesecore.certificate.ca.its.region.ItsSupportedCountries;
import org.cesecore.certificate.ca.its.region.RectangularRegions;

/**
 * 
 *
 */
public final class EditCaUtil {
    
    private static final Logger log = Logger.getLogger(EditCaUtil.class);

    public static final String MANAGE_CA_NAV = "managecas";
    public static final String EDIT_CA_NAV = "editcapage";
    public static final String SIGN_CERT_REQ_NAV = "recievefile";
    public static final String DISPLAY_RESULT_NAV = "displayresult";
    public static final int CERTREQGENMODE = 0;
    public static final int CERTGENMODE = 1;
    public static final String LINK_CERT_BASE_URI = "cacertreq?cmd=linkcert&";
    public static final String CA_EXPORT_PATH = "/ca/exportca";
    public static final String TEXTFIELD_EXPORTCA_PASSWORD = org.ejbca.ui.web.admin.cainterface.CAExportServlet.TEXTFIELD_EXPORTCA_PASSWORD;
    public static final String HIDDEN_CANAME = org.ejbca.ui.web.admin.cainterface.CAExportServlet.HIDDEN_CANAME;
    
    public static String getTrimmedName(final String name) {
        if (name != null && !name.isEmpty()) {
            return name.replaceAll("\\([^()]*\\)", StringUtils.EMPTY).replaceAll(", ", StringUtils.EMPTY);
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    public static void navigateToManageCaPageIfNotPostBack() {
        if (!FacesContext.getCurrentInstance().isPostback()) {
            try {
                FacesContext.getCurrentInstance().getExternalContext().redirect(EditCaUtil.MANAGE_CA_NAV + ".xhtml");
            } catch (IOException e) {
                throw new FacesException("Cannot redirect to " + EditCaUtil.MANAGE_CA_NAV + " due to IO exception.", e);
            }
        }         
    }
    
    public static List<String> getAllGeographicRegionTypes(){
        List<String> regionTypes = new ArrayList<>();
        for(ItsGeographicRegion.RegionType region: ItsGeographicRegion.RegionType.values()) {
            regionTypes.add(region.getDisplayName());
        }
        return regionTypes;
    }
    
    public static String getRegionPreview(String regionTypeString, String description) {
        if(StringUtils.isEmpty(regionTypeString)||StringUtils.isEmpty(description)) {
            // initial case or user is yet to provide description
            // also identified country without region
            return "";
        }
        ItsGeographicRegion.RegionType regionType = 
                ItsGeographicRegion.RegionType.fromDisplayName(regionTypeString);
        switch(regionType) {
            case CIRCULAR:
                CircularRegion region = new CircularRegion(description);
                return region.getGuiDescription().get(0);
            case RECTANGULAR:
                RectangularRegions region2 = new RectangularRegions(description + ItsGeographicRegion.SEQUENCE_SEPARATOR);
                return region2.getGuiDescription().get(0);
            case IDENTIFIED:
            default:
                // for identified region, there is only one list of regions
                return "";
        }
    } 
    
    /**
     * Adds or removes GUI elements for geographic regions.
     * 
     * @param selectedGeographicRegionType
     * @param geographicElementsInGui
     * @param addRegion
     */
    public static void addGeographicRegionGui(String selectedGeographicRegionType, 
            List<ItsGeographicRegionGuiWrapper> geographicElementsInGui){
        
        ItsGeographicRegionGuiWrapper guiWrapper = new ItsGeographicRegionGuiWrapper();;
        ItsGeographicRegion.RegionType regionType = 
                ItsGeographicRegion.RegionType.fromDisplayName(selectedGeographicRegionType);
        guiWrapper.setType(regionType.getDisplayName());
        
        switch(regionType) {
            case CIRCULAR:
                if(geographicElementsInGui.size()!=0) {
                    throw new IllegalArgumentException("Circular geographic region expects one geoElement in GUI. "
                                                            + "Please remove other elements");
                }
                guiWrapper.setName(regionType.getDisplayName() + " region");
                guiWrapper.setSequentialType(false);
                guiWrapper.setHelpText(CircularRegion.CIRCLE_FORMAT_HINT);
                break;
            case RECTANGULAR:
                guiWrapper.setName(regionType.getDisplayName() + " region " + (geographicElementsInGui.size()+1));
                guiWrapper.setSequentialType(true);
                guiWrapper.setHelpText(RectangularRegions.RECTANGLE_FORMAT_HINT);
                break;
            case IDENTIFIED:
                // covers both country and country region
                guiWrapper.setName(regionType.getDisplayName() + " region " + (geographicElementsInGui.size()+1));
                guiWrapper.setSequentialType(true);
                guiWrapper.setHelpText(IdentifiedRegionCountryRegions.COUNTRY_REGION_HINT);
                guiWrapper.setValidOptions(ItsSupportedCountries.getSupportedCountryNames());
                guiWrapper.setCountry(ItsSupportedCountries.WHOLE_EUROPE.getDisplayName());
                break;
            case NONE:
            default:
                throw new IllegalArgumentException("Please select a valid geographic element.");
            
        }
        geographicElementsInGui.add(guiWrapper);

    }
    
    /**
     * Returns ItsGeographicElement which is used for persistence and to get BC compatible classes.
     * 
     * It expects a top level catch on IllegalArgumentException and IllegalStateException 
     * for validations in EJBCA and BC.
     * 
     * @param selectedGeographicRegionType
     * @param geographicElementsInGui
     * @return
     */
    public static ItsGeographicElement getGeographicRegion(String selectedGeographicRegionType, 
            List<ItsGeographicRegionGuiWrapper> geographicElementsInGui){
        
        if(geographicElementsInGui.isEmpty()) {
            return null; //alternate select default region here(worldwide/whole Europe)
        }
        
        ItsGeographicRegion.RegionType regionType = 
                ItsGeographicRegion.RegionType.fromDisplayName(selectedGeographicRegionType);
        ItsGeographicElement geoElement = null;
        String errorString = ""; //
        StringBuilder description = new StringBuilder();
        int i = 0;
               
        switch(regionType) {
            case CIRCULAR:
                if(geographicElementsInGui.size()!=1) {
                    errorString = "Circular geographic region expects one geoElement in GUI.";
                    log.debug(errorString);
                    throw new IllegalArgumentException(errorString);
                }
                geoElement = new CircularRegion(geographicElementsInGui.get(0).getDescription());
                break;
            case RECTANGULAR:
                for(ItsGeographicRegionGuiWrapper guiWrapper: geographicElementsInGui) {
                    i++;
                    if(StringUtils.isEmpty(guiWrapper.getDescription())) {
                        errorString = "Please enter the coordinates in geographic element: " + i;
                        log.debug(errorString);
                        throw new IllegalArgumentException(errorString);
                    }
                    description.append(guiWrapper.getDescription());
                    description.append(ItsGeographicRegion.SEQUENCE_SEPARATOR);
                }
                geoElement = new RectangularRegions(description.toString());
                break;
            case IDENTIFIED:
                // covers both country and country region
                for(ItsGeographicRegionGuiWrapper guiWrapper: geographicElementsInGui) {
                    i++; // one-based
                    if(guiWrapper.getCountry().equals(ItsSupportedCountries.WHOLE_EUROPE.getDisplayName()) && 
                            !StringUtils.isEmpty(guiWrapper.getDescription())) {
                        errorString = "Please select the country in which region belongs in geographic element: " + i;
                        log.debug(errorString);
                        throw new IllegalArgumentException(errorString);
                    }
                    if(StringUtils.isEmpty(guiWrapper.getDescription())) {
                        description.append(ItsGeographicRegion.REGION_TYPE_IDENTIFIED_COUNTRY);
                        description.append(guiWrapper.getCountry());
                    } else {
                        description.append(ItsGeographicRegion.REGION_TYPE_IDENTIFIED_COUNTRY_REGION);
                        description.append(guiWrapper.getCountry());
                        description.append(ItsGeographicRegion.SEPARATOR);
                        description.append(guiWrapper.getDescription());
                    }
                    
                    description.append(ItsGeographicRegion.SEQUENCE_SEPARATOR);
                }
                geoElement = new IdentifiedRegions(description.toString());
                break;
            case NONE:
            default:
                //alternate select default region here(worldwide/whole Europe)
                break;
        }
        
        return geoElement;
    }

    public static void loadGeographicRegionsForGui(List<ItsGeographicRegionGuiWrapper> geographicElementsInGui, ItsGeographicRegion region) {        
        ItsGeographicRegion.RegionType regionType = region.getRegionType();
        ItsGeographicRegionGuiWrapper guiWrapper = null;
        String regionDescription = region.getGeographicElement().toStringFormat();
        regionDescription = regionDescription.substring(
                                    regionDescription.indexOf(ItsGeographicRegion.TYPE_SEPARATOR)+1);
        String[] descriptions = regionDescription.split(ItsGeographicRegion.SEQUENCE_SEPARATOR);
        switch(regionType) {
            case CIRCULAR:
                guiWrapper = new ItsGeographicRegionGuiWrapper();
                guiWrapper.setType(regionType.getDisplayName());
                guiWrapper.setName(regionType.getDisplayName() + " region");
                guiWrapper.setDescription(regionDescription);
                guiWrapper.setPreviewText(region.getGeographicElement().getGuiDescription().get(0));
                guiWrapper.setHelpText(CircularRegion.CIRCLE_FORMAT_HINT);
                geographicElementsInGui.add(guiWrapper);
                break;
            case RECTANGULAR:
                int i=0;
                for(String guiString: region.getGeographicElement().getGuiDescription()) {
                    guiWrapper = new ItsGeographicRegionGuiWrapper();
                    guiWrapper.setType(regionType.getDisplayName());
                    guiWrapper.setName(regionType.getDisplayName() + " region " + (geographicElementsInGui.size()+1));
                    guiWrapper.setDescription(descriptions[i]);
                    guiWrapper.setPreviewText(guiString);
                    guiWrapper.setHelpText(RectangularRegions.RECTANGLE_FORMAT_HINT);
                    geographicElementsInGui.add(guiWrapper);
                    i++;
                }
                break;
            case IDENTIFIED:
                int j=0, split;
                for(String guiString: region.getGeographicElement().getGuiDescription()) {
                    guiWrapper = new ItsGeographicRegionGuiWrapper();
                    guiWrapper.setType(regionType.getDisplayName());
                    guiWrapper.setName(regionType.getDisplayName() + " region " + (geographicElementsInGui.size()+1));
                    split = descriptions[j].indexOf(ItsGeographicRegion.SEPARATOR);
                    if(split!=-1) {
                        guiWrapper.setDescription(descriptions[j].substring(split+1));
                        guiWrapper.setCountry(
                                descriptions[j].substring(descriptions[j].indexOf(ItsGeographicRegion.TYPE_SEPARATOR)+1, 
                                        descriptions[j].indexOf(ItsGeographicRegion.SEPARATOR)));
                    } else {
                        guiWrapper.setDescription("");
                        guiWrapper.setCountry(
                                descriptions[j].substring(descriptions[j].indexOf(ItsGeographicRegion.TYPE_SEPARATOR)+1));
                    }
                    guiWrapper.setHelpText(IdentifiedRegionCountryRegions.COUNTRY_REGION_HINT);
                    guiWrapper.setPreviewText(guiString);
                    guiWrapper.setValidOptions(ItsSupportedCountries.getSupportedCountryNames());
                    geographicElementsInGui.add(guiWrapper);
                    j++;
                }
                break;
            case NONE:
            default:
                //should never happen
                throw new IllegalArgumentException("Invalid geographic element.");
        }
    }

    /**
     * Acts also as an validation layer.
     * @param geographicElementsInGui
     */
    public static void updateGeographicRegions(List<ItsGeographicRegionGuiWrapper> geographicElementsInGui) {
        for(int i=0; i<geographicElementsInGui.size(); i++) {
            ItsGeographicRegionGuiWrapper guiWrapper = geographicElementsInGui.get(i);
            if(guiWrapper.isToRemove()) {
                geographicElementsInGui.remove(i);
                i--;
                continue;
            }
            String previewText = "";
            try {
                previewText = EditCaUtil.getRegionPreview(guiWrapper.getType(), guiWrapper.getDescription());
            } catch (Exception e) { // may catch exceptions from BC
                log.info("Invalid geographic element:" + e.getMessage());
                previewText = "Provided description is invalid";
            }
            if(StringUtils.isNotEmpty(previewText)) {
                guiWrapper.setPreviewText(previewText);
            }
        }
        return;
    }
    
}
