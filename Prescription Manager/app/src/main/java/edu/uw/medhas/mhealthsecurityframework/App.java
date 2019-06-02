package edu.uw.medhas.mhealthsecurityframework;

import android.app.Application;
import android.arch.persistence.room.Room;

import edu.uw.medhas.mhealthsecurityframework.model.secureDatabaseModel.entity.SecureDatabase;

/**
 * Created by medhasrivastava on 1/24/19.
 */

public class App extends Application {
    private static App INSTANCE;

    private static final String sDbName = "secure_db";
    private SecureDatabase db;

    public static App get() {
        return INSTANCE;
    }

    @Override
    public void onCreate() {
        super.onCreate();

        db = Room.databaseBuilder(getApplicationContext(), SecureDatabase.class, sDbName)
                .allowMainThreadQueries()
                .fallbackToDestructiveMigration()
                .build();

        INSTANCE = this;
    }

    public SecureDatabase getDb() {
        return db;
    }
}
