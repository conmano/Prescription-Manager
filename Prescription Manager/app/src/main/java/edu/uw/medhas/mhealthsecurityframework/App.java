package edu.uw.medhas.mhealthsecurityframework;

import android.app.Application;
import android.arch.persistence.room.Room;

import edu.uw.medhas.mhealthsecurityframework.model.secureDatabaseModel.entity.SecureDatabase;

public class App extends Application {

    //Creates instance of the app

    private static App INSTANCE;

    //Creates database and creates name for it

    private static final String sDbName = "secure_db";
    private SecureDatabase db;

    //returns the instance of the app

    public static App get() {
        return INSTANCE;
    }

    @Override
    public void onCreate() {
        super.onCreate();

        //Builds the database

        db = Room.databaseBuilder(getApplicationContext(), SecureDatabase.class, sDbName)
                .allowMainThreadQueries()
                .fallbackToDestructiveMigration()
                .build();

        //Instance is = the app (this)

        INSTANCE = this;
    }

    //returns database

    public SecureDatabase getDb() {
        return db;
    }
}
