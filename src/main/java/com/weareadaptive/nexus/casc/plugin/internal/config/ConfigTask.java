package com.weareadaptive.nexus.casc.plugin.internal.config;

public class ConfigTask {
    private String name;
    private boolean enabled = true;
    private String typeName;
    private String typeId;
    private String alertEmail;
    private String notificationCondition;

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getTypeId() {
        return typeId;
    }

    public void setTypeId(final String typeId) {
        this.typeId = typeId;
    }

    public Boolean getEnabled() {
        return enabled;
    }
    public Boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final Boolean enabled) {
        this.enabled = enabled;
    }

    public String getTypeName() {
        return typeName;
    }

    public void setTypeName(final String typeName) {
        this.typeName = typeName;
    }

    public String getAlertEmail() {
        return alertEmail;
    }

    public void setAlertEmail(final String alertEmail) {
        this.alertEmail = alertEmail;
    }

    public String getNotificationCondition() {
        return notificationCondition;
    }

    public void setNotificationCondition(String notificationCondition) {
        this.notificationCondition = notificationCondition;
    }
}
