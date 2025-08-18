package com.programandoenjava.jwt.util;

import java.util.Arrays;
import java.util.List;

public enum Role {

    CUSTOMER(Arrays.asList(Permission.READ_ALL_USERS)),
    ADMINISTRATOR(Arrays.asList(Permission.WRITE_ALL_USERS, Permission.READ_ALL_USERS, Permission.DELETE_ALL_USERS));

    private Role() {
        // Constructor is private to prevent instantiation
    }

    Role(List<Permission> permissions) {
        this.permissions = permissions;
    }

    private List<Permission> permissions;

    public List<Permission> getPermissions() {
        return permissions;
    }
}
