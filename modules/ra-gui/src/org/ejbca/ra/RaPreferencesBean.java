package org.ejbca.ra;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;

import org.apache.log4j.Logger;
import org.cesecore.config.RaStyleInfo;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;

@ManagedBean
@ViewScoped
public class RaPreferencesBean implements Converter, Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaPreferencesBean.class);

    private static final String CURRENTRALOCALE = "currentRaLocale";
    private static final String CURRENTRASTYLE = "currentRaStyle";

    @EJB
    private AdminPreferenceSessionLocal adminPreferenceSession;
    
    @ManagedProperty(value = "#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) {
        this.raLocaleBean = raLocaleBean;
    }

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    
    public void setRaAuthenticationBean(RaAuthenticationBean raAuthenticationBean) {
        this.raAuthenticationBean = raAuthenticationBean;
    }
    
    private Locale currentLocale;

    private RaStyleInfo currentStyle;
    
    @PostConstruct
    public void init() {

        LinkedHashMap<String, Object> raStyleInfoHash = adminPreferenceSession.getCurrentRaStyleInfoAndLocale(raAuthenticationBean.getAuthenticationToken());
        
        if(raStyleInfoHash != null) {
            currentLocale = (Locale)raStyleInfoHash.get(CURRENTRALOCALE);
            currentStyle = (RaStyleInfo)raStyleInfoHash.get(CURRENTRASTYLE);
            raLocaleBean.setLocale(currentLocale);
        } else {
            currentLocale = raLocaleBean.getLocale();
        }
    }
    
    public RaStyleInfo getCurrentStyle() {
        return currentStyle;
    }

    public void setCurrentStyle(final RaStyleInfo currentStyle) {
        this.currentStyle = currentStyle;
    }

    public Locale getCurrentLocale() {
        return currentLocale;
    }

    public void setCurrentLocale(final Locale locale) {

        this.currentLocale = locale;
        raLocaleBean.setLocale(locale);
    }
    
    public List<Locale> getLocales() {
        return raLocaleBean.getSupportedLocales();
    }
    
    public List<RaStyleInfo> getStyles() {
        return adminPreferenceSession.getAvailableRaStyleInfos(raAuthenticationBean.getAuthenticationToken());
    }
    
    public void updatePreferences() {

        LinkedHashMap<String, Object> infoToUpdate = new LinkedHashMap<>();
        
        infoToUpdate.put(CURRENTRALOCALE, currentLocale);
        infoToUpdate.put(CURRENTRASTYLE, currentStyle);

        adminPreferenceSession.setCurrentRaStyleInfo(infoToUpdate, raAuthenticationBean.getAuthenticationToken());
    }
    
    /**
     * The following two methods are used in converting RaStyleInfo to String and vice versa.
     * Required by JSF.
     */
    @Override
    public Object getAsObject(FacesContext context, UIComponent component, String value) {
        
        List<RaStyleInfo> styleInfos = adminPreferenceSession.getAvailableRaStyleInfos(raAuthenticationBean.getAuthenticationToken());
        
        for (RaStyleInfo raStyleInfo: styleInfos) {
            if (raStyleInfo.getArchiveName().equals(value)) {
                return raStyleInfo;
            }
        }
        
        return null;
    }

    @Override
    public String getAsString(FacesContext context, UIComponent component, Object value) {

        RaStyleInfo raStyleInfo = (RaStyleInfo) value;
        
        return raStyleInfo.getArchiveName();
    }

    /**
     * Used to reset the preferences page
     * @return
     */
    public String reset() {
        String viewId = FacesContext.getCurrentInstance().getViewRoot().getViewId();
        return viewId+"?faces-redirect=true";
    }


}
