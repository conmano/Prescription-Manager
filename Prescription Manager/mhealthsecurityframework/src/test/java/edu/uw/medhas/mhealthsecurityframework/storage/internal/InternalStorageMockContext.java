package edu.uw.medhas.mhealthsecurityframework.storage.internal;

import org.junit.rules.TemporaryFolder;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.uw.medhas.mhealthsecurityframework.storage.AbstractStorageMockContext;

/**
 * Created by medhas on 11/3/18.
 */

public class InternalStorageMockContext extends AbstractStorageMockContext {
    private final int fileMode;

    private FileOutputStream mockFos;
    private FileInputStream mockFis;

    public InternalStorageMockContext(int fileMode, TemporaryFolder tempFolder) {
        super(tempFolder);
        this.fileMode = fileMode;
    }

    public void mockFosWrite(Exception ex) throws IOException {
        mockFos = Mockito.mock(FileOutputStream.class);
        if (ex != null) {
            Mockito.doThrow(ex).when(mockFos).write(ArgumentMatchers.any(byte[].class));
        } else {
            Mockito.doNothing().when(mockFos).write(ArgumentMatchers.any(byte[].class));
        }
    }

    public void mockFisIOException() throws IOException {
        mockFis = Mockito.mock(FileInputStream.class);
        Mockito.when(mockFis.read(ArgumentMatchers.any(byte[].class))).thenThrow(new IOException());
    }

    @Override
    public FileInputStream openFileInput(String name) throws FileNotFoundException {
        if (getFileThatExists().getName().equals(name)) {
            if (mockFis == null && getFis() == null) {
                throw new FileNotFoundException();
            } else if (getFis() != null) {
                return getFis();
            } else {
                return mockFis;
            }
        } else {
            return super.openFileInput(name);
        }
    }

    @Override
    public File getFileStreamPath(String name) {
        if (getFileThatExists().getName().equals(name)) {
            return getFileThatExists();
        } else {
            return new File(name);
        }
    }

    @Override
    public FileOutputStream openFileOutput(String name, int mode) throws FileNotFoundException {
        if (getFileName().equals(name) && fileMode == mode) {
            return mockFos;
        } else {
            return super.openFileOutput(name, mode);
        }
    }
}
