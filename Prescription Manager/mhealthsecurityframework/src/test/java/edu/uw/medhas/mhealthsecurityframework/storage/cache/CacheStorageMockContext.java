package edu.uw.medhas.mhealthsecurityframework.storage.cache;

import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import edu.uw.medhas.mhealthsecurityframework.storage.AbstractStorageMockContext;

/**
 * Created by medhas on 11/3/18.
 */

public class CacheStorageMockContext extends AbstractStorageMockContext {
    int count = 0;
    int invalidEnvDirectoryThreshold = 10;

    public CacheStorageMockContext(TemporaryFolder tempFolder) {
        super(tempFolder);
    }

    public void setInvalidEnvDirectoryThreshold(int invalidEnvDirectoryThreshold) {
        this.invalidEnvDirectoryThreshold = invalidEnvDirectoryThreshold;
    }

    public void mockFosIOException() throws IOException {
        final File file = getTempFolder().newFile(getFileName());
        file.setReadOnly();
    }

    @Override
    public File getCacheDir() {
        return (++count < invalidEnvDirectoryThreshold)
                ? super.getTempFolder().getRoot()
                : new File(UUID.randomUUID().toString());
    }
}
