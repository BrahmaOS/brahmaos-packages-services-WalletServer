package com.android.server.wallet;

import android.content.Context;
import android.util.Log;

public class WalletSystem {
    private static final String TAG = "WalletSystem";
    private WalletServiceImpl mWalletServiceImpl;

    public interface Component {
        WalletSystem getWalletSystem();
    }
    /**
     * Tagging interface for the object used for synchronizing multi-threaded operations in
     * the Wallet system.
     */
    public interface SyncRoot {
    }

    private static WalletSystem INSTANCE = null;
    private final SyncRoot mLock = new SyncRoot() { };

    public static WalletSystem getInstance() {
        return INSTANCE;
    }

    public static void setInstance(WalletSystem instance) {
        if (null == INSTANCE) {
            INSTANCE = instance;
            Log.d(TAG, "WalletSystem.INSTANCE begin set");
        } else {
            Log.d(TAG, "Attempt to set WalletSystem.INSTANCE twice");
        }
    }

    public WalletSystem(Context context) {
        mWalletServiceImpl = new WalletServiceImpl(context, mLock);
    }

    public WalletServiceImpl getmWalletServiceImpl() {
        return mWalletServiceImpl;
    }
    public Object getLock() {
        return mLock;
    }
}
