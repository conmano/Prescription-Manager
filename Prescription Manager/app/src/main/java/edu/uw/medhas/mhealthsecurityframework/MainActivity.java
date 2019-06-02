package edu.uw.medhas.mhealthsecurityframework;

import android.content.Context;
import android.os.Bundle;
import android.os.Environment;
import android.support.design.widget.NavigationView;
import android.support.v4.view.GravityCompat;
import android.support.v4.widget.DrawerLayout;
import android.support.v7.app.ActionBarDrawerToggle;
import android.support.v7.widget.Toolbar;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import edu.uw.medhas.mhealthsecurityframework.acl.db.DbError;
import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Privilege;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;
import edu.uw.medhas.mhealthsecurityframework.acl.model.User;
import edu.uw.medhas.mhealthsecurityframework.acl.model.UserRole;
import edu.uw.medhas.mhealthsecurityframework.acl.service.PrivilegeService;
import edu.uw.medhas.mhealthsecurityframework.acl.service.RoleService;
import edu.uw.medhas.mhealthsecurityframework.acl.service.UserService;
import edu.uw.medhas.mhealthsecurityframework.activity.SecureActivity;
import edu.uw.medhas.mhealthsecurityframework.model.SecureAnnotatedModel;
import edu.uw.medhas.mhealthsecurityframework.model.SecureSerializableModel;
import edu.uw.medhas.mhealthsecurityframework.model.secureDatabaseModel.entity.SecureDatabase;
import edu.uw.medhas.mhealthsecurityframework.model.secureDatabaseModel.entity.SensitiveDbData;
import edu.uw.medhas.mhealthsecurityframework.password.PasswordUtils;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoLowerCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoNumberCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoSpecialCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoUpperCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordTooShortException;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureDouble;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureFloat;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureInteger;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureLong;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureString;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.ReauthenticationException;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageReadObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageWriteObject;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResult;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultSuccess;
import edu.uw.medhas.mhealthsecurityframework.web.model.Request;
import edu.uw.medhas.mhealthsecurityframework.web.model.RequestMethod;
import edu.uw.medhas.mhealthsecurityframework.web.model.Response;
import edu.uw.medhas.mhealthsecurityframework.web.model.WebError;
import edu.uw.medhas.mhealthsecurityframework.web.model.ResponseHandler;
import edu.uw.medhas.mhealthsecurityframework.webclient.TestWebClient;


//This is the beginning of main

public class MainActivity extends SecureActivity
        implements NavigationView.OnNavigationItemSelectedListener {


    //Database using App.java

    private SecureDatabase mSecureDatabase;
    @Override

    //When app is created
    //Sets up database using the framework, deletes keys from android keystore

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
                this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close);
        drawer.addDrawerListener(toggle);
        toggle.syncState();

        NavigationView navigationView = (NavigationView) findViewById(R.id.nav_view);
        navigationView.setNavigationItemSelectedListener(this);

        mSecureDatabase = App.get().getDb();

        // Delete keys
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            keyStore.deleteEntry("mhealth-security-framework-internal-storage");
            keyStore.deleteEntry("mhealth-security-framework-external-storage");
            keyStore.deleteEntry("mhealth-security-framework-database-storage");
            keyStore.deleteEntry("mhealth-security-framework-cache-storage");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

    }

    @Override

    //When the back button is pressed on the phone

    public void onBackPressed() {
        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        if (drawer.isDrawerOpen(GravityCompat.START)) {
            drawer.closeDrawer(GravityCompat.START);
        } else {
            super.onBackPressed();
        }
    }

    @Override

    //This is for the navigation bar that can come out
    //Allows people to select different menu items

    public boolean onNavigationItemSelected(MenuItem item) {
        // Handle navigation view item clicks here.
        int id = item.getItemId();

        View newView = null;
        final LayoutInflater inflater = (LayoutInflater)getSystemService(Context.LAYOUT_INFLATER_SERVICE);


        //Pulls up the xml file for whatever they chose

        if (id == R.id.nav_password_be) {
            newView = inflater.inflate(R.layout.content_pwdvalidator_be, null);
        } else if (id == R.id.nav_internal_annotation) {
            newView = inflater.inflate(R.layout.content_intsto_ano, null);
        } else if (id == R.id.nav_acl_user) {
            newView = inflater.inflate(R.layout.content_acl_user, null);
        } else if (id == R.id.nav_acl_privilege) {
            newView = inflater.inflate(R.layout.content_acl_privilege, null);
        }


        // Resets the views

        LinearLayout mainLayout = (LinearLayout) findViewById(R.id.main_container);
        mainLayout.removeAllViews();
        mainLayout.addView(newView);


        //To Create an account

        if (id == R.id.nav_password_be) {
            final EditText editTextUs = (EditText) findViewById(R.id.username);
            final EditText editTextPw = (EditText) findViewById(R.id.passwordBe);
            final TextView editTextOp = (TextView) findViewById(R.id.validatePasswordBeOp);
            final Button btnValidatePassword = (Button) findViewById(R.id.validatePasswordBe);
            final TextView editTextOp2 = (TextView) findViewById(R.id.validateCreateAccount);
            final EditText editTextUs2 = (EditText) findViewById(R.id.userAuth);
            final UserService userService = getAclServiceFactory().getUserService();


            btnValidatePassword.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    editTextOp.setText("");
                    final String passwordStr = editTextPw.getText().toString();

                    //Checks password

                    try {
                        PasswordUtils.validatePassword(passwordStr);
                        editTextOp.setText("Password is strong");
                    } catch (PasswordTooShortException ptsex) {
                        editTextOp.setText("Password is too small");
                    } catch (PasswordNoUpperCaseCharacterException pnuccex) {
                        editTextOp.setText("Password has no upper case character");
                    } catch (PasswordNoLowerCaseCharacterException pnlccex) {
                        editTextOp.setText("Password has no lower case character");
                    } catch (PasswordNoNumberCharacterException pnncex) {
                        editTextOp.setText("Password has no number");
                    } catch (PasswordNoSpecialCharacterException pnscex) {
                        editTextOp.setText("Password has no special character");
                    }

                    //Need to get password to store with username


                    //Gets Username and attempts to insert. Can't figure how to bypass authentication though

                    final User user = new User();
                    user.setId(editTextUs.getText().toString());
                    user.setName(user.getId() + "-name");

                    final AuthContext context = new AuthContext(editTextUs2.getText().toString());

                    userService.createUser(user, context, new ResultHandler<User>() {
                        @Override
                        public void onSuccess(User result) {
                            editTextOp2.setText("Successfully created User: " + result.getId());
                        }
                        @Override
                        public void onFailure(DbError error) {
                            editTextOp2.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });

                }
            });


            //Stores prescription data
            //Uses authentication to check if it can use either function

        } else if (id == R.id.nav_internal_annotation) {

            final EditText editTextInp = (EditText) findViewById(R.id.intAnoSensitiveInp);
            final Button btnStore = (Button) findViewById(R.id.intAnoStore);
            final TextView editTextOp = (TextView) findViewById(R.id.intAnoSensitiveOp);
            final Button btnRetrieve = (Button) findViewById(R.id.intAnoRetrieve);
            final UserService userService = getAclServiceFactory().getUserService();

            //To store prescription data

            btnStore.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final SecureAnnotatedModel sam = new SecureAnnotatedModel();
                    sam.setData(editTextInp.getText().toString());

                    final StorageWriteObject<SecureAnnotatedModel> writeObject =
                            new StorageWriteObject<>("internalstorage-annotation.txt", sam);

                    getSecureInternalFileHandler().writeData(writeObject,
                            new StorageResultCallback<StorageResultSuccess>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(StorageResult<StorageResultSuccess> storageResult) {
                                    editTextOp.setText("Successfully stored file");
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("WebError storing file: " + errorType.name());
                                }
                            });
                }
            });


            //retrieves prescription data

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final StorageReadObject<SecureAnnotatedModel> readObject =
                            new StorageReadObject<>("internalstorage-annotation.txt",
                                    SecureAnnotatedModel.class);

                    getSecureInternalFileHandler().readData(readObject,
                            new StorageResultCallback<SecureAnnotatedModel>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(StorageResult<SecureAnnotatedModel> storageResult) {
                                    editTextOp.setText(storageResult.getResult().getData());
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("WebError retrieving file: " + errorType.name());
                                }
                            });
                }
            });

            //Allows the creation of new users

        } else if (id == R.id.nav_acl_user) {
            final EditText editTextNewUser = (EditText) findViewById(R.id.aclUserNewUser);
            final EditText editTextCurrentUser = (EditText) findViewById(R.id.aclUserCurrentUser);
            final Button btnCreate = (Button) findViewById(R.id.aclUserCreate);
            final Button btnDelete = (Button) findViewById(R.id.aclUserDelete);
            final TextView editTextOp = (TextView) findViewById(R.id.aclUserOp);
            final UserService userService = getAclServiceFactory().getUserService();


            //Creates User

            btnCreate.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final User user = new User();
                    user.setId(editTextNewUser.getText().toString());
                    user.setName(user.getId() + "-name");

                    final AuthContext context = new AuthContext(editTextCurrentUser.getText().toString());

                    userService.createUser(user, context, new ResultHandler<User>() {
                        @Override
                        public void onSuccess(User result) {
                            editTextOp.setText("Successfully created User: " + result.getId());
                        }

                        @Override
                        public void onFailure(DbError error) {
                            editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });
                }
            });


            //Deletes User

            btnDelete.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final String userId = editTextNewUser.getText().toString();
                    final AuthContext context = new AuthContext(editTextCurrentUser.getText().toString());

                    userService.deleteUser(userId, context, new ResultHandler<Void>() {
                        @Override
                        public void onSuccess(Void result) {
                            editTextOp.setText("Successfully deleted User");
                        }

                        @Override
                        public void onFailure(DbError error) {
                            editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });
                }
            });

            //Allows for new roles to be given to users

        } else if (id == R.id.nav_acl_privilege) {
            final EditText editTextNewRole = (EditText) findViewById(R.id.aclRoleNewRole);
            final EditText editTextCurrentUser = (EditText) findViewById(R.id.aclRoleCurrentUser);
            final Button btnCreate = (Button) findViewById(R.id.aclRoleCreate);
            final TextView editTextOp = (TextView) findViewById(R.id.aclRoleOp);

            final RoleService roleService = getAclServiceFactory().getRoleService();

            //Gives new role to user

            btnCreate.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final Role role = new Role();
                    role.setName(editTextNewRole.getText().toString());

                    final AuthContext context = new AuthContext(editTextCurrentUser.getText().toString());

                    roleService.createRole(role, context, new ResultHandler<Role>() {
                        @Override
                        public void onSuccess(Role result) {
                            editTextOp.setText("Successfully created Role: " + result.getId());
                        }

                        @Override
                        public void onFailure(DbError error) {
                            editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });
                }
            });
        }

        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        drawer.closeDrawer(GravityCompat.START);
        return true;
    }
}
