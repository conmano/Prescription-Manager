package edu.uw.medhas.mhealthsecurityframework.password;

import org.junit.Test;

import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoLowerCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoNumberCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoSpecialCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoUpperCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordTooShortException;

import static org.junit.Assert.assertEquals;

/**
 * Created by medhas on 10/23/18.
 */

public class PasswordUtilsTest {

    @Test(expected = PasswordTooShortException.class)
    public void validatePassword_short() throws Exception {
        PasswordUtils.validatePassword("small");
    }

    @Test(expected = PasswordNoUpperCaseCharacterException.class)
    public void validatePassword_lowercase() throws Exception {
        PasswordUtils.validatePassword("nouppercase");
    }

    @Test(expected = PasswordNoLowerCaseCharacterException.class)
    public void validatePassword_uppercase() throws Exception {
        PasswordUtils.validatePassword("NOLOWERCASE");
    }

    @Test(expected = PasswordNoNumberCharacterException.class)
    public void validatePassword_number() throws Exception {
        PasswordUtils.validatePassword("NoNumberChar");
    }

    @Test(expected = PasswordNoSpecialCharacterException.class)
    public void validatePassword_specialChar() throws Exception {
        PasswordUtils.validatePassword("N0Sp3c1aLchAr");
    }

    @Test(expected = Test.None.class)
    public void validatePassword_allValidationsPassed() throws Exception {
        PasswordUtils.validatePassword("P3rfecTPassw0rD!@#");
    }
}
