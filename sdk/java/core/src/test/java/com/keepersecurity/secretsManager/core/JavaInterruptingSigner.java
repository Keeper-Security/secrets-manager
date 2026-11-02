package com.keepersecurity.secretsManager.core;

// A Java caller follows the KDoc: keyLocation may throw InterruptedException.
public class JavaInterruptingSigner implements RequestSigner {
    @Override
    public byte[] sign(byte[] data) throws InterruptedException { return new byte[64]; }

    @Override
    public String getKeyLocation() throws InterruptedException { throw new InterruptedException("cancelled"); }

    @Override
    public void onBound(AppData appData) {}
}
