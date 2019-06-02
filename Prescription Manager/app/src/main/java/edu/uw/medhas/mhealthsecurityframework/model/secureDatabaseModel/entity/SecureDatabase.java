package edu.uw.medhas.mhealthsecurityframework.model.secureDatabaseModel.entity;

import android.arch.persistence.room.*;
import android.arch.persistence.room.Database;

/**
 * Created by medhasrivastava on 1/24/19.
 */

@Database(entities = {SensitiveDbData.class}, version = 9, exportSchema = false)
public abstract class SecureDatabase extends RoomDatabase {

    public abstract DaoAccess daoAccess() ;
}
