package edu.uw.medhas.mhealthsecurityframework.model.secureDatabaseModel.entity;

import android.arch.persistence.room.*;
import android.support.annotation.NonNull;

import edu.uw.medhas.mhealthsecurityframework.storage.database.converters.SecureDoubleConverter;
import edu.uw.medhas.mhealthsecurityframework.storage.database.converters.SecureFloatConverter;
import edu.uw.medhas.mhealthsecurityframework.storage.database.converters.SecureIntegerConverter;
import edu.uw.medhas.mhealthsecurityframework.storage.database.converters.SecureLongConverter;
import edu.uw.medhas.mhealthsecurityframework.storage.database.converters.SecureStringConverter;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureDouble;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureFloat;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureInteger;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureLong;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureString;

/**
 * Created by medhasrivastava on 1/24/19.
 */

@Entity(tableName = "sensitive_db_data")
public class SensitiveDbData {
    @NonNull
    @PrimaryKey(autoGenerate = true)
    private int id;

    @TypeConverters(SecureIntegerConverter.class)
    private SecureInteger intValue;

    @TypeConverters(SecureDoubleConverter.class)
    private SecureDouble doubleValue;

    @TypeConverters(SecureFloatConverter.class)
    private SecureFloat floatValue;

    @TypeConverters(SecureLongConverter.class)
    private SecureLong longValue;

    @TypeConverters(SecureStringConverter.class)
    private SecureString stringValue;

    private String simpleStr;

    public SensitiveDbData(){
    }

    @NonNull
    public Integer getId() {
        return id;
    }

    public void setId(@NonNull Integer id) {
        this.id = id;
    }

    public SecureInteger getIntValue() {
        return intValue;
    }

    public void setIntValue(SecureInteger intValue) {
        this.intValue = intValue;
    }

    public SecureDouble getDoubleValue() {
        return doubleValue;
    }

    public void setDoubleValue(SecureDouble doubleValue) {
        this.doubleValue = doubleValue;
    }

    public SecureFloat getFloatValue() {
        return floatValue;
    }

    public void setFloatValue(SecureFloat floatValue) {
        this.floatValue = floatValue;
    }

    public SecureLong getLongValue() {
        return longValue;
    }

    public void setLongValue(SecureLong longValue) {
        this.longValue = longValue;
    }

    public SecureString getStringValue() {
        return stringValue;
    }

    public void setStringValue(SecureString stringValue) {
        this.stringValue = stringValue;
    }

    public String getSimpleStr() {
        return simpleStr;
    }

    public void setSimpleStr(String simpleStr) {
        this.simpleStr = simpleStr;
    }
}
