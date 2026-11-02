package com.keepersecurity.secretsManager.core;

// A Java protector can return null from wrap, which Kotlin callers cannot write.
public class NullWrapProtector implements AppKeyProtector {
    @Override
    public byte[] wrap(byte[] appKey) { return null; }

    @Override
    public byte[] unwrap(byte[] wrappedAppKey) { return null; }
}
