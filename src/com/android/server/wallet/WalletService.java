package com.android.server.wallet;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public class WalletService extends Service implements WalletSystem.Component{
    private static final String TAG = "WalletService";

    private void initializeWalletSystem() {
        if (null == getWalletSystem()) {
            WalletSystem.setInstance(new WalletSystem(this));
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        Log.d(TAG, "onBind");
        initializeWalletSystem();
        synchronized (getWalletSystem().getLock()) {
            return getWalletSystem().getmWalletServiceImpl().getBinder();
        }
    }

    @Override
    public WalletSystem getWalletSystem() {
        return WalletSystem.getInstance();
    }
}
