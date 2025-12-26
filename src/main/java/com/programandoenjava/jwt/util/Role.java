package com.programandoenjava.jwt.util;

import java.util.Arrays;
import java.util.List;

public enum Role {

    ADMIN(Arrays.asList(
            Permission.ACCOUNTS_READ,
            Permission.ACCOUNTS_WRITE,
            Permission.TRANSFERS_CREATE,
            Permission.BENEFICIARIES_MANAGE
    )),
    TELLER(Arrays.asList(
            Permission.ACCOUNTS_READ,
            Permission.ACCOUNTS_WRITE,
            Permission.TRANSFERS_CREATE
    )),
    CUSTOMER(Arrays.asList(
            Permission.ACCOUNTS_READ
    ));

    private List<Permission> permissions;

    Role(List<Permission> permissions) {
        this.permissions = permissions;
    }

    public List<Permission> getPermissions() {
        return permissions;
    }
}