package com.weareadaptive.nexus.casc.plugin.internal.config;

public class ConfigTaskSchedule {
    private Boolean removed;
    private ConfigTask task;
    private ConfigSchedule schedule;

    public Boolean isRemoved() {
        return removed;
    }
    public Boolean getRemoved() {
        return removed;
    }

    public void setRemoved(final Boolean removed) {
        this.removed = removed;
    }

    public ConfigTask getTask() {
        return task;
    }

    public void setTask(final ConfigTask taskConfig) {
        this.task = taskConfig;
    }

    public ConfigSchedule getSchedule() {
        return schedule;
    }

    public void setSchedule(final ConfigSchedule taskSchedule) {
        this.schedule = taskSchedule;
    }
}
