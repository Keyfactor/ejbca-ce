package org.ejbca.ra;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;
import javax.faces.convert.FacesConverter;

import org.cesecore.config.RaStyleInfo;

/**
 * Used in preferences section of RA GUI to convert selected theme and make it digestible by server and vice versa.
 *
 * @version $Id: LocaleConverter.java 26057 2017-06-22 08:08:34Z anatom $
 *
 */
@FacesConverter("themeConverter")
public class ThemeConverter implements Converter {

    @Override
    public Object getAsObject(FacesContext context, UIComponent component, String value) {

        if (value == null || value.isEmpty()) {
            return null;
        }
        return null;
    }

    @Override
    public String getAsString(FacesContext context, UIComponent component, Object value) {

        RaStyleInfo raStyleInfo = (RaStyleInfo) value;
        
        return raStyleInfo.getArchiveName();
    }

}