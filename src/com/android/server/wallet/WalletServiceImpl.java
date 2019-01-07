package com.android.server.wallet;

import brahmaos.app.IWalletManager;
import brahmaos.app.WalletManager;
import brahmaos.content.BrahmaIntent;
import brahmaos.content.TransactionDetails;
import brahmaos.content.WalletData;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.os.PersistableBundle;
import android.os.RemoteException;
import android.os.UserHandle;
import android.os.UserManager;
import android.util.AtomicFile;
import brahmaos.content.BrahmaConstants;
import brahmaos.util.DataCryptoUtils;
import android.util.Log;
import android.util.Xml;

import com.android.internal.annotations.GuardedBy;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.core.listeners.TransactionConfidenceEventListener;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDUtils;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bitcoinj.wallet.Wallet.SendResult;

import org.spongycastle.util.encoders.Hex;

import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Wallet;
import org.web3j.crypto.WalletFile;
import org.web3j.crypto.WalletUtils;

import org.web3j.utils.Numeric;
import org.web3j.utils.Convert;

import org.web3j.protocol.Web3j;
import org.web3j.protocol.Web3jFactory;
import org.web3j.protocol.ObjectMapperFactory;
import org.web3j.protocol.http.HttpService;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthGasPrice;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.core.methods.response.EthTransaction;

import org.web3j.tx.RawTransactionManager;
import org.web3j.tx.TransactionManager;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Uint256;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import libcore.io.IoUtils;
import org.xmlpull.v1.XmlSerializer;

import com.android.internal.util.FastXmlSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Splitter;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;

import rx.Completable;
import rx.Observable;
import rx.Observer;
import rx.Subscriber;
import rx.android.schedulers.AndroidSchedulers;
import rx.schedulers.Schedulers;

import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;

import static brahmaos.app.WalletManager.CODE_ERROR_PASSWORD;
import static brahmaos.app.WalletManager.CODE_NO_ERROR;
import static brahmaos.app.WalletManager.KYBER_NETWORK_ETH_ADDRESS;
import static brahmaos.app.WalletManager.WALLET_CHAIN_TYPE_BTC;
import static brahmaos.app.WalletManager.WALLET_CHAIN_TYPE_ETH;

public class WalletServiceImpl {
    private static final String TAG = "WalletServiceImpl";
    private static final boolean DEBUG = true;

    // define tags and attrs used in the xml
    private static final String TAG_WALLETS = "wallets";
    private static final String TAG_WALLET = "wallet";

    private static final String ATTR_ADDRESS = "address";
    private static final String ATTR_ISDEFAULT = "isDefault";
    private static final String ATTR_KEY_PATH = "keyPath";
    private static final String ATTR_PRIVATEKEY_STR = "privateKeyStr";
    private static final String ATTR_MNEMONIC_STR = "mnemonicStr";

    private static final String TAG_CREATE_TIME = "createTime";
    private static final String TAG_LAST_UPDATE_TIME = "lastUpdateTime";
    private static final String TAG_NAME = "name";
    private static final String TAG_AVATAR_PATH = "avatar";
    private static final String TAG_KEYSTORE = "keystore";
    private static final String TAG_KIT_FILE_NAME = "kitFileName";

    private static final String WALLET_DATA_DIR = "system";
    // record wallet list and each wallet's address
    private static final String WALLET_LIST_FILENAME = "walletlist.xml";
    private static final String XML_SUFFIX = ".xml";

    private final File mWalletDir;
    private final File mWalletListFile;

    private static final String CHECK_POINTS_NAME = "checkpoints_mainnet";
//    private static final String CHECK_POINTS_NAME = "checkpoints_testnet";//for test only
    private Context mContext;

    private final WalletSystem.SyncRoot mLock;
    private HashMap<String, WalletData> mWalletsMap = new HashMap<>();//<address, WalletData>

    private final Object mKitLock = new Object();
    private HashMap<String, WalletAppKit> mBTCWalletKits = new HashMap<>();//<kitFileName, WalletAppKit>

    private final Object mDownloadedListLock = new Object();
    // record the kitFileName of bitcoin wallets which are done downloaded
    private ArrayList<String> mBTCDownloaded = new ArrayList<>();

    private String[] mWalletAddresses;

    public WalletServiceImpl(Context context, WalletSystem.SyncRoot lock) {
        mContext = context;
        mLock = lock;
        synchronized (mLock) {
            mWalletDir = new File(Environment.getDataDirectory(), WALLET_DATA_DIR);
            if (mWalletDir.exists()) {
                mWalletDir.mkdir();
            }
            mWalletListFile = new File(mWalletDir, WALLET_LIST_FILENAME);
            if (!mWalletListFile.exists()) {
                try {
                    mWalletListFile.createNewFile();
                } catch (Exception e) {
                    if (DEBUG) {
                        Log.d(TAG, "Failed to create file " + mWalletListFile.getAbsolutePath());
                    }
                }
            }
            readWalletListL();
        }
    }

    private final IWalletManager.Stub mBinderImpl = new IWalletManager.Stub() {
        /**
         * @hide
         */
        @Override
        public List<WalletData> createDefaultWallet(String name, String mnemonics,
                                                    String password, boolean isCreation) {
            if (null == name || name.isEmpty() || null == mnemonics || mnemonics.isEmpty() ||
                    !isValidPassword(password)) {
                Log.d(TAG, "createDefaultWallet with empty param.");
                return null;
            }
            Log.d(TAG, "begin createDefaultWallet");

            List<WalletData> wallets = new ArrayList<>();

            boolean hasDefaultETH = false;
            boolean hasDefaultBTC = false;
            List<WalletData> existWallets = getAllWallets();
            if (existWallets != null && existWallets.size() > 0) {
                for (WalletData walletData : existWallets) {
                    if (walletData.isDefault) {
                        if (BrahmaConstants.BIP_ETH_PATH.equalsIgnoreCase(walletData.keyPath)) {
                            hasDefaultETH = true;
                        } else if (BrahmaConstants.BIP_BTC_PATH.equalsIgnoreCase(walletData.keyPath)) {
                            hasDefaultBTC = true;
                        }
                    }
                }
            }

            if(!hasDefaultETH) {
                WalletData ethWallet = generateETHWalletByMnemonic(name + "_ETH", mnemonics, password);
                if (null != ethWallet) {
                    wallets.add(ethWallet);
                }
                ethWallet.isDefault = true;
            } else {
                Log.d(TAG, "already has default ethereum wallet.");
            }

            if(!hasDefaultBTC) {
                WalletData btcWallet = generateBTCWalletByMnemonic(name + "_BTC", mnemonics,
                        password, isCreation);
                if (null != btcWallet) {
                    wallets.add(btcWallet);
                }
                btcWallet.isDefault = true;
            } else {
                Log.d(TAG, "already has default bitcoin wallet.");
            }

            if (wallets.size() <= 0) {
                return null;
            }
            synchronized (mLock) {
                for (WalletData walletData : wallets) {
                    mWalletsMap.put(walletData.address, walletData);
                    writeWalletL(walletData);
                }
                writeWalletListL();
            }
            return wallets;
        }

        @Override
        public List<WalletData> createWallet(String name, String password) {
            List<WalletData> wallets = new ArrayList<>();
            WalletData ethWallet = createEthereumWallet(name + "_ETH", password);
            if (ethWallet != null) {
                wallets.add(ethWallet);
            }
            WalletData btcWallet = createBitcoinWallet(name + "_BTC", password);
            if (ethWallet != null) {
                wallets.add(btcWallet);
            }
            return wallets;
        }

        @Override
        public WalletData createEthereumWallet(String name,String password) {
            Log.d(TAG, "begin createEthereumWallet");
            if (!isValidWalletName(name)) {
                Log.d(TAG, "createEthereumWallet--name " + name + " has been repeated or empty.");
                return null;
            }
            if (!isValidPassword(password)) {
                Log.d(TAG, "createEthereumWallet--invalid password, the minimum length is 6.");
                return null;
            }
            String mnemonics = generateMnemonics();
            if (null == mnemonics || mnemonics.isEmpty()) {
                return null;
            }
            WalletData walletData = generateETHWalletByMnemonic(name, mnemonics, password);
            if (null == walletData) {
                return null;
            }

            /**only store encrypted mnemonics string when creating new wallet**/
            walletData.mnemonicStr = DataCryptoUtils.aes128Encrypt(mnemonics, password);

            synchronized (mLock) {
                mWalletsMap.put(walletData.address, walletData);
                writeWalletL(walletData);
                writeWalletListL();
            }
            return walletData;
        }

        @Override
        public WalletData createBitcoinWallet(String name, String password) {
            Log.d(TAG, "begin createBitcoinWallet");
            if (!isValidWalletName(name)) {
                Log.d(TAG, "createBitcoinWallet--name " + name + " has been repeated or empty.");
                return null;
            }
            if (!isValidPassword(password)) {
                Log.d(TAG, "createBitcoinWallet--invalid password, length must be longer than 6.");
                return null;
            }
            String mnemonics = generateMnemonics();
            if (null == mnemonics || mnemonics.isEmpty()) {
                return null;
            }
            WalletData walletData = generateBTCWalletByMnemonic(name, mnemonics, password, true);
            if (null == walletData) {
                return null;
            }

            synchronized (mLock) {
                mWalletsMap.put(walletData.address, walletData);
                writeWalletL(walletData);
                writeWalletListL();
            }
            return walletData;
       }

        @Override
        public WalletData importEthereumWallet(String name, String password, String data, int dataType) {
            if (null == data) {
                Log.d(TAG, "importEthereumWallet--The data must not be empty!");
                return null;
            }
            if (!isValidWalletName(name)) {
                Log.d(TAG, "importEthereumWallet--name " + name + " has been repeated or empty.");
                return null;
            }
            if (!isValidPassword(password)) {
                Log.d(TAG, "importEthereumWallet--invalid password, length must be longer than 6.");
                return null;
            }
            WalletData walletData = null;
            if (WalletManager.IMPORT_BY_PRIVATE_KEY == dataType) {
                walletData = generateETHWalletByPrivateKey(name, data, password);
            } else if (WalletManager.IMPORT_BY_MNEMONICS == dataType) {
                walletData = generateETHWalletByMnemonic(name,data,password);
            } else if (WalletManager.IMPORT_BY_KEYSTORE == dataType) {
                walletData = generateETHWalletByKeyStore(name, data, password);
            } else {
                walletData = null;
                Log.d(TAG, "No the match dataType value to import Ethereum wallet by the data.");
            }
            if (null == walletData) {
                return null;
            }
            if (mWalletsMap.containsKey(walletData.address)) {
                Log.d(TAG, walletData.address + " already exist!");
                return null;
            }
            synchronized (mLock) {
                mWalletsMap.put(walletData.address, walletData);
                writeWalletL(walletData);
                writeWalletListL();
            }
            return walletData;
        }

        @Override
        public WalletData importBitcoinWallet(String name, String password, String data, int dataType) {
            if (null == data) {
                Log.d(TAG, "importBitcoinWallet--The data must not be empty!");
                return null;
            }
            if (!isValidWalletName(name)) {
                Log.d(TAG, "importBitcoinWallet--name " + name + " has been repeated or empty.");
                return null;
            }
            if (!isValidPassword(password)) {
                Log.d(TAG, "importBitcoinWallet--invalid password, length must be longer than 6.");
                return null;
            }
            WalletData walletData;
            if (WalletManager.IMPORT_BY_MNEMONICS == dataType) {
                walletData = generateBTCWalletByMnemonic(name, data, password, false);
            } else {
                walletData = null;
                Log.d(TAG, "No the match dataType value to import Bitcoin wallet by the data.");
            }
            if (null == walletData) {
                return null;
            }
            synchronized (mLock) {
                mWalletsMap.put(walletData.address, walletData);
                writeWalletL(walletData);
                writeWalletListL();
            }
            return walletData;
        }

        @Override
        public String exportEthereumWalletPrivateKey(String address, String password) {
            if (!isValidAddress(address, WALLET_CHAIN_TYPE_ETH)) {
                Log.d(TAG, "exportEthereumWalletPrivateKey--invalid address: " + address);
                return null;
            }
            if (!isValidPassword(password)) {
                Log.d(TAG, "exportEthereumWalletPrivateKey--invalid password.");
                return null;
            }
            WalletData walletData = mWalletsMap.get(address);
            if (walletData != null) {
                try {
                    ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
                    WalletFile walletFile = objectMapper.readValue(walletData.keyStore, WalletFile.class);
                    Credentials credentials = Credentials.create(Wallet.decrypt(password, walletFile));
                    BigInteger privateKey = credentials.getEcKeyPair().getPrivateKey();
                    return privateKey.toString(16);
                } catch (Exception e) {
                    Log.e(TAG, "exportEthereumWalletPrivateKey--" + e.toString());
                    return null;
                }
            } else {
                Log.d(TAG, "exportEthereumWalletPrivateKey--wallet not exist.");
                return null;
            }
        }

        private WalletAppKit getBitcoinWalletAppKit(String address) {
            if (!isValidAddress(address, WALLET_CHAIN_TYPE_BTC)) {
                Log.d(TAG, "getBitcoinWalletAppKit--invalid address: " + address);
                return null;
            }
            WalletData walletData = mWalletsMap.get(address);
            if (walletData != null && walletData.kitFileName != null && !walletData.kitFileName.isEmpty()) {
                return mBTCWalletKits.get(walletData.kitFileName);
            } else {
                Log.d(TAG, "getBitcoinWalletAppKit--no match wallet exist for " + address);
            }
            return null;
        }

        @Override
        public int getBitcoinPrivateKeysCount(String mainAddress) {
            if (DEBUG) {
                Log.d(TAG, "getBitcoinPrivateKeysCount--" + mainAddress);
            }
            WalletAppKit kit = getBitcoinWalletAppKit(mainAddress);
            if (kit != null && kit.wallet() != null) {
                return kit.wallet().getActiveKeyChain().getIssuedExternalKeys()
                        + kit.wallet().getActiveKeyChain().getIssuedInternalKeys();
            } else {
                Log.d(TAG, "getBitcoinPrivateKeysCount--can not get WalletAppKit.");
                return -1;
            }
        }

        @Override
        public int getBitcoinLastBlockSeenHeight(String mainAddress) {
            if (DEBUG) {
                Log.d(TAG, "getBitcoinLastBlockSeenHeight--" + mainAddress);
            }
            WalletAppKit kit = getBitcoinWalletAppKit(mainAddress);
            if (kit != null && kit.wallet() != null) {
                return kit.wallet().getLastBlockSeenHeight();
            } else {
                Log.d(TAG, "getBitcoinLastBlockSeenHeight--can not get WalletAppKit.");
                return -1;
            }
        }

        @Override
        public String getBitcoinLastBlockSeenTime(String mainAddress) {
            if (DEBUG) {
                Log.d(TAG, "getBitcoinLastBlockSeenTime--" + mainAddress);
            }
            WalletAppKit kit = getBitcoinWalletAppKit(mainAddress);
            if (kit != null && kit.wallet() != null) {
                return kit.wallet().getLastBlockSeenTime() ==
                        null ? null : Utils.dateTimeFormat(kit.wallet().getLastBlockSeenTime());
            } else {
                Log.d(TAG, "getBitcoinLastBlockSeenTime--can not get WalletAppKit.");
                return null;
            }
        }

        @Override
        public long getBitcoinPendingTxAmount(String mainAddress) {
            if (DEBUG) {
                Log.d(TAG, "getBitcoinPendingTxAmount--" + mainAddress);
            }
            WalletAppKit kit = getBitcoinWalletAppKit(mainAddress);
            if (kit != null && kit.wallet() != null && !kit.wallet().getPendingTransactions().isEmpty()) {
                Iterator iterator = kit.wallet().getPendingTransactions().iterator();
                if (iterator.hasNext()) {
                    org.bitcoinj.core.Transaction transaction = (org.bitcoinj.core.Transaction) iterator.next();
                    return transaction.getValue(kit.wallet()).value;
                } else {
                    return 0;
                }
            } else {
                Log.d(TAG, "getBitcoinLastBlockSeenTime--can not get WalletAppKit.");
                return 0;
            }
        }

        @Override
        public String getBitcoinCurrentReceiveAddress(String mainAddress) {
            if (DEBUG) {
                Log.d(TAG, "getBitcoinCurrentReceiveAddress--" + mainAddress);
            }
            WalletAppKit kit = getBitcoinWalletAppKit(mainAddress);
            if (kit != null && kit.wallet() != null) {
                return kit.wallet().currentReceiveAddress().toBase58();
            } else {
                Log.d(TAG, "getBitcoinCurrentReceiveAddress--can not get WalletAppKit.");
                return null;
            }
        }

        @Override
        public boolean checkBitcoinDoneDownloaded(String mainAddress) {
            if (null == mainAddress) {
                return false;
            }
            WalletData data = mWalletsMap.get(mainAddress);
            if (null == data || null == data.kitFileName || data.kitFileName.isEmpty()
                    || !mBTCWalletKits.containsKey(data.kitFileName)) {
                Log.d(TAG, mainAddress + " not exist.");
                return false;
            }
            if (mBTCDownloaded.contains(data.kitFileName)) {
                return true;
            }

            return false;
        }

        @Override
        public boolean checkPasswordForWallet(WalletData walletData, String password) {
            if (null == walletData || !isValidPassword(password)) {
                return false;
            }
            if (walletData.keyPath.startsWith(WALLET_CHAIN_TYPE_ETH)) {
                try {
                    //Check the password by the keyStore.
                    ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
                    WalletFile walletFile = objectMapper.readValue(
                            walletData.keyStore, WalletFile.class);
                    return isValidKeystore(walletFile, password);
                } catch (Exception exception) {
                    return false;
                }
            } else if (walletData.keyPath.startsWith(WALLET_CHAIN_TYPE_BTC)) {
                return isValidMnemonic(walletData.mnemonicStr, password);
            }
            return true;
        }

        @Override
        public int deleteWalletByAddress(String address, String password) {
            Log.d(TAG, "begin deleteWalletByAddress--" + address);

            if (null == address || address.isEmpty()) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            WalletData needDeleteWallet = mWalletsMap.get(address);
            if (null == needDeleteWallet) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            if (needDeleteWallet.isDefault) {
                return WalletManager.CODE_DEFAULT_WALLET_CANNOT_DELETE;
            }

            if (!checkPasswordForWallet(needDeleteWallet, password)) {
                return CODE_ERROR_PASSWORD;
            }

            // Remove WalletAppKit files for BTC wallet first.
            if (BrahmaConstants.BIP_BTC_PATH.equalsIgnoreCase(needDeleteWallet.keyPath)) {
                WalletAppKit kit = mBTCWalletKits.get(needDeleteWallet.kitFileName);
                try {
                    kit.stopAsync();
                    kit.awaitTerminated();
                } catch (Exception e) {
                    Log.e(TAG, "Failed to deleteWalletByAddress--" + e.toString());
                    return WalletManager.CODE_WALLET_EXCEPTION;
                }
                synchronized (mKitLock) {
                    mBTCWalletKits.remove(needDeleteWallet.kitFileName);
                    deleteBTCFiles(needDeleteWallet.kitFileName);
                }
            }
            // Update the wallet list
            synchronized (mLock) {
                mWalletsMap.remove(address);
                writeWalletListL();
            }
            // Remove wallet file
            AtomicFile walletFile = new AtomicFile(new File(mWalletDir, address + XML_SUFFIX));
            if (walletFile != null && walletFile.exists()) {
                walletFile.delete();
            }
            synchronized (mLock) {
                updateWalletAddresses();
            }
            return WalletManager.CODE_NO_ERROR;
        }

        @Override
        public int updateWalletNameForAddress(String newName, String address) {
            Log.d(TAG, "begin updateWalletNameForAddress: " + address);
            if (null == address || address.isEmpty()) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            WalletData walletData = mWalletsMap.get(address);
            if (null == walletData) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            if (!isValidWalletName(newName)) {
                return WalletManager.CODE_REPEAT_NAME;
            }
            walletData.name = newName;
            walletData.lastUpdateTime = System.currentTimeMillis() / 1000;
            synchronized (mLock) {
                mWalletsMap.put(walletData.address, walletData);
                writeWalletL(walletData);
                writeWalletListL();
                return WalletManager.CODE_NO_ERROR;
            }
        }

        @Override
        public int updateWalletAvatarForAddress(String newAvatar, String address) {
            Log.d(TAG, "begin updateWalletAvatarForAddress" + address);
            if (null == newAvatar || newAvatar.isEmpty()) {
                return WalletManager.CODE_OTHER_ERROR;
            }
            if (null == address || address.isEmpty()) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            WalletData walletData = mWalletsMap.get(address);
            if (null == walletData) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            walletData.avatar = newAvatar;
            walletData.lastUpdateTime = System.currentTimeMillis() / 1000;
            synchronized (mLock) {
                mWalletsMap.put(walletData.address, walletData);
                writeWalletL(walletData);
                writeWalletListL();
                return WalletManager.CODE_NO_ERROR;
            }
        }

        @Override
        public int updateWalletPasswordForAddress(String address, String oldPassword, String newPassword) {
            Log.d(TAG, "updateWalletPasswordForAddress " + address);
            if (null == address || address.isEmpty()) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            if (!isValidPassword(oldPassword) || !isValidPassword(newPassword)) {
                return WalletManager.CODE_ERROR_PASSWORD;
            }
            WalletData walletData = mWalletsMap.get(address);
            if (walletData != null && walletData.keyPath != null) {
                if (walletData.keyPath.startsWith(WALLET_CHAIN_TYPE_ETH)) {
                    return updateEthereumWalletPassword(address, oldPassword, newPassword);
                } else if (walletData.keyPath.startsWith(WALLET_CHAIN_TYPE_BTC)) {
                    return updateBitcoinWalletPassword(address, oldPassword, newPassword);
                }
            }
            return WalletManager.CODE_WALLET_NOT_EXIST;
        }

        @Override
        public int updateEthereumWalletPassword(String address, String oldPassword, String newPassword) {
            Log.d(TAG, "begin updateEthereumWalletPassword");
            if (null == address || address.isEmpty()) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            if (!isValidPassword(oldPassword) || !isValidPassword(newPassword)) {
                return WalletManager.CODE_ERROR_PASSWORD;
            }
            if (mWalletsMap.containsKey(address)) {
                WalletData needUpdateWalletData = mWalletsMap.get(address);
                try {
                    // Check the old password by the old keyStore
                    ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
                    BigInteger privateKey;
                    try {
                        WalletFile oldWalletFile = objectMapper.readValue(
                                needUpdateWalletData.keyStore, WalletFile.class);
                        Credentials credentials = Credentials.create(Wallet.decrypt(oldPassword, oldWalletFile));
                        privateKey = credentials.getEcKeyPair().getPrivateKey();
                        if (!WalletUtils.isValidPrivateKey(privateKey.toString(16))) {
                            return WalletManager.CODE_ERROR_PASSWORD;
                        }
                    } catch (CipherException exception) {
                        return WalletManager.CODE_ERROR_PASSWORD;
                    }

                    ECKeyPair ecKeyPair = ECKeyPair.create(privateKey);

                    if (ecKeyPair != null) {
                        WalletFile walletFile = Wallet.createLight(newPassword, ecKeyPair);

                        // If new WalletFile's address changed for Ethereum Wallet, return false.
                        String addr = Numeric.prependHexPrefix(walletFile.getAddress());
                        if (!needUpdateWalletData.address.equalsIgnoreCase(addr)) {
                            Log.d(TAG, "has generated new address: " + addr);
                            return WalletManager.CODE_WALLET_EXCEPTION;
                        }

                        // get keystore string
                        needUpdateWalletData.keyStore = objectMapper.writeValueAsString(walletFile);
                        needUpdateWalletData.lastUpdateTime = System.currentTimeMillis() / 1000;
                    }
                } catch (Exception e) {
                    Log.e(TAG, "createDefaultETWallet fail: " + e.toString());
                    return WalletManager.CODE_WALLET_EXCEPTION;
                }
                synchronized (mLock) {
                    mWalletsMap.put(address, needUpdateWalletData);
                    writeWalletL(needUpdateWalletData);
                    writeWalletListL();
                    return WalletManager.CODE_NO_ERROR;
                }
            } else {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
        }

        @Override
        public int updateBitcoinWalletPassword(String address, String oldPassword, String newPassword) {
            Log.d(TAG, "begin updateBitcoinWalletPassword");
            if (null == address || address.isEmpty()) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            if (!isValidPassword(oldPassword) || !isValidPassword(newPassword)) {
                return WalletManager.CODE_ERROR_PASSWORD;
            }
            if (mWalletsMap.containsKey(address)) {
                WalletData needUpdateWalletData = mWalletsMap.get(address);
                if (!isValidMnemonic(needUpdateWalletData.mnemonicStr, oldPassword)) {
                    return WalletManager.CODE_ERROR_PASSWORD;
                }
                String mnemonic = DataCryptoUtils.aes128Decrypt(
                        needUpdateWalletData.mnemonicStr, oldPassword);
                needUpdateWalletData.mnemonicStr = DataCryptoUtils.aes128Encrypt(mnemonic, newPassword);

                synchronized (mLock) {
                    mWalletsMap.put(address, needUpdateWalletData);
                    writeWalletL(needUpdateWalletData);
                    writeWalletListL();
                    return WalletManager.CODE_NO_ERROR;
                }
            } else {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
        }

        @Override
        public List<WalletData> getAllWallets() {
            int allSize = mWalletsMap.size();
            if (allSize <= 0) {
                return null;
            }
            List<WalletData> wallets = new ArrayList<>();

            Iterator<Map.Entry<String, WalletData>> ir = mWalletsMap.entrySet().iterator();
            while (ir.hasNext()) {
                wallets.add(ir.next().getValue());
            }
            return wallets;
        }

        @Override
        public List<WalletData> getWalletsForChainType(String chainType) {
            int allSize = mWalletsMap.size();
            if (allSize <= 0) {
                return null;
            }
            List<WalletData> walletsForChainType = new ArrayList<>();
            WalletData tempData;

            Iterator<Map.Entry<String, WalletData>> ir = mWalletsMap.entrySet().iterator();
            while (ir.hasNext()) {
                tempData = ir.next().getValue();
                // keyPath is the full chain path, and chain type is the sub string
                // of keyPath from start to coin type
                if (tempData.keyPath.startsWith(chainType)) {
                    walletsForChainType.add(tempData);
                }
            }
            return walletsForChainType;
        }

        @Override
        public WalletData getWalletDataByAddress(String address) {
            if (null == address || address.isEmpty()) {
                return null;
            }
            return mWalletsMap.get(address);
        }

        @Override
        public boolean isValidAddress(String address, String chainType) {
            if (null == address || address.isEmpty()) {
                return false;
            }
            if (WALLET_CHAIN_TYPE_ETH.equalsIgnoreCase(chainType)) {
                return address.length() >= 2 &&
                        address.charAt(0) == '0' && address.charAt(1) == 'x' &&
                        WalletUtils.isValidAddress(address);
            } else if (WalletManager.WALLET_CHAIN_TYPE_BTC.equalsIgnoreCase(chainType)) {
                try {
                    org.bitcoinj.core.Address.fromBase58(getNetworkParams(), address);
                    return true;
                } catch (Exception e) {
                    e.fillInStackTrace();
                    return false;
                }
            } else {
                return true;
            }
        }

        @Override
        public String getEthereumBalanceStringByAddress(String networkUrl, String addr, String tokenAddr) {
            if (null == networkUrl || networkUrl.isEmpty()) {
                networkUrl = WalletManager.MAINNET_URL;
            }
            if (DEBUG) {
                Log.d(TAG, "getEthereumBalanceStringByAddress----" + networkUrl);
            }
            if (!isValidAddress(addr, WALLET_CHAIN_TYPE_ETH)) {
                Log.d(TAG, "getEthereumBalanceStringByAddress----invalid address " + addr);
                return null;
            }
            Web3j web3 = Web3jFactory.build(new HttpService(networkUrl));
            if (null == tokenAddr || tokenAddr.isEmpty()) {//means ethereum account
                try {
                    EthGetBalance ethBalance = web3.ethGetBalance(addr, DefaultBlockParameterName.LATEST)
                                               .send();
                    if (DEBUG) {
                        Log.d(TAG, "ETH " + addr + ": " + ethBalance.getBalance());
                    }
                    if (ethBalance != null && ethBalance.getBalance() != null) {
                        return ethBalance.getBalance().toString();
                    } else {
                        return null;
                    }
                } catch (IOException e) {
                    Log.e(TAG, addr + " eth get balance failed: " + e.toString());
                    return null;
                }
            } else {//means token
                Function function = new Function(
                        "balanceOf",
                        Arrays.asList(new Address(addr)),// Solidity Types in smart contract functions
                        Arrays.asList(new TypeReference<Uint256>() {
                        }));

                String encodedFunction = FunctionEncoder.encode(function);
                Transaction trans = Transaction.createEthCallTransaction(addr, tokenAddr, encodedFunction);

                try {
                    EthCall ethCall = web3.ethCall(trans, DefaultBlockParameterName.LATEST)
                            .send();
                    if (ethCall != null && ethCall.getValue() != null) {
                        if (DEBUG) {
                            Log.d(TAG, tokenAddr + ": " + ethCall.getValue());
                        }
                        return Numeric.decodeQuantity(ethCall.getValue()).toString();
                    } else {
                        return null;
                    }
                } catch (Exception e) {
                    Log.e(TAG, addr + " token get balance failed: " + e.toString());
                    return null;
                }
            }
        }

        @Override
        public String getEthereumGasPrice(String networkUrl) {
            if (null == networkUrl || networkUrl.isEmpty()) {
                networkUrl = WalletManager.MAINNET_URL;
            }
            if (DEBUG) {
                Log.d(TAG, "getEthereumGasPrice----" + networkUrl);
            }
            try {
                Web3j web3j = Web3jFactory.build(new HttpService(networkUrl));
                final EthGasPrice ethGasPrice = web3j.ethGasPrice().send();
                BigDecimal gasPriceGwei = Convert.fromWei(
                        new BigDecimal(ethGasPrice.getGasPrice()), Convert.Unit.GWEI);
                return gasPriceGwei.toString();
            } catch (Exception e) {
                Log.e(TAG, "getEthereumGasPrice--" + e.toString());
                return null;
            }
        }

        /**
         * @param src the String value of source ERC20 token contract address
         * @param dest the String value of destination ERC20 token contract address
         *
         * @return the expected exchange rate and slippage rate with unit wei. Note that these returned values
         *         are in 18 decimals regardless of the destination token's decimals.
         **/
        @Override
        public List<String> getExpectedRate(String networkUrl, String src, String dest) {
            if (null == networkUrl || networkUrl.isEmpty()) {
                networkUrl = WalletManager.MAINNET_URL;
            }
            if (DEBUG) {
                Log.d(TAG, "getExpectedRate----" + networkUrl);
            }
            try {
                Web3j web3j = Web3jFactory.build(new HttpService(networkUrl));
                String rateContractAddress = WalletManager.KYBER_MAIN_NETWORK_ADDRESS;
                if (networkUrl.equals(WalletManager.ROPSTEN_TEST_URL)) {
                    rateContractAddress = WalletManager.KYBER_ROPSTEN_NETWORK_ADDRESS;
                }
                Function function = new Function("getExpectedRate",
                        Arrays.<Type>asList(new Address(src),
                                new Address(dest),
                                new Uint256(BigInteger.ONE)),
                        Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}, new TypeReference<Uint256>() {}));
                String encodedFunction = FunctionEncoder.encode(function);
                EthCall ethCall = web3j.ethCall(
                        Transaction.createEthCallTransaction(
                                "0x0000000000000000000000000000000000000000",
                                rateContractAddress, encodedFunction),
                        DefaultBlockParameterName.LATEST)
                        .send();

                String rateValue = ethCall.getValue();
                Log.d(TAG, "the kyber wrapper contract rate original result : " + rateValue);
                List<Type> values = FunctionReturnDecoder.decode(rateValue, function.getOutputParameters());
                List<String> rateResult = new ArrayList<>();
                for (Type rates : values) {
                    Uint256 rate = (Uint256) rates;
                    // get the String value of rate with unit "wei".
                    rateResult.add(rate.getValue().toString());
                }
                return rateResult;
            } catch (Exception e) {
                Log.e(TAG, "getExpectedRate--" + e.toString());
                return null;
            }
        }

        @Override
        public String approveKyberNetwork(String networkUrl, String src, double amount, String walletAddress,
                                          String password, double gasPrice, long gasLimit) {
            if (null == networkUrl || networkUrl.isEmpty()) {
                networkUrl = WalletManager.MAINNET_URL;
            }
            if (DEBUG) {
                Log.d(TAG, "approveKyberNetwork----" + networkUrl);
            }
            try {
                Web3j web3j = Web3jFactory.build(new HttpService(networkUrl));
                WalletData wallet = getWalletDataByAddress(walletAddress);
                if (null == wallet || null == wallet.keyPath || wallet.keyStore.isEmpty()) {
                    Log.d(TAG, "wallet " + walletAddress + " not exist.");
                    return null;
                }
                Credentials credentials = null;
                try {
                    ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
                    WalletFile walletFile = objectMapper.readValue(wallet.keyStore, WalletFile.class);
                    credentials = Credentials.create(Wallet.decrypt(password, walletFile));
                } catch (Exception e) {
                    Log.d(TAG, "approveKyberNetwork--Error: password is wrong!");
                    return null;
                }

                String kyberContractAddress = WalletManager.KYBER_MAIN_NETWORK_ADDRESS;
                if (networkUrl.equals(WalletManager.ROPSTEN_TEST_URL)) {
                    kyberContractAddress = WalletManager.KYBER_ROPSTEN_NETWORK_ADDRESS;
                }
                Function function = new Function(
                        "approve",
                        Arrays.<Type>asList(new Address(kyberContractAddress),
                                new Uint256(BigDecimal.valueOf(amount).multiply(new BigDecimal(Math.pow(10, 18))).toBigInteger())),
                        Collections.<TypeReference<?>>emptyList());
                String encodedFunction = FunctionEncoder.encode(function);

                RawTransactionManager txManager = new RawTransactionManager(web3j, credentials);
                EthSendTransaction transactionResponse = txManager.sendTransaction(
                        Convert.toWei(BigDecimal.valueOf(gasPrice), Convert.Unit.GWEI).toBigIntegerExact(),
                        BigInteger.valueOf(gasLimit), src, encodedFunction, BigInteger.ZERO);

                if (transactionResponse.hasError()) {
                    Log.e(TAG, "approveKyberNetwork--Error processing transaction request: "
                            + transactionResponse.getError().getMessage());
                    return null;
                }
                return transactionResponse.getTransactionHash();
            } catch (Exception e) {
                Log.e(TAG, "approveKyberNetwork--" + e.toString());
                return null;
            }
        }

        @Override
        public String getContractAllowance(String networkUrl, String walletAddress, String src) {
            if (null == networkUrl || networkUrl.isEmpty()) {
                networkUrl = WalletManager.MAINNET_URL;
            }
            if (DEBUG) {
                Log.d(TAG, "getContractAllowance----" + networkUrl);
            }
            try {
                Web3j web3j = Web3jFactory.build(new HttpService(networkUrl));
                String kyberContractAddress = WalletManager.KYBER_MAIN_NETWORK_ADDRESS;
                if (networkUrl.equals(WalletManager.ROPSTEN_TEST_URL)) {
                    kyberContractAddress = WalletManager.KYBER_ROPSTEN_NETWORK_ADDRESS;
                }
                Function function = new Function(
                        "allowance",
                        Arrays.<Type>asList(new Address(walletAddress),
                                new Address(kyberContractAddress)),
                        Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}));
                String encodedFunction = FunctionEncoder.encode(function);

                EthCall ethCall = web3j.ethCall(
                        Transaction.createEthCallTransaction(
                                "0x0000000000000000000000000000000000000000",
                                src, encodedFunction),
                        DefaultBlockParameterName.LATEST).send();

                String enableResult = ethCall.getValue();

                List<Type> values = FunctionReturnDecoder.decode(enableResult, function.getOutputParameters());
                Uint256 allowAmount = (Uint256) values.get(0);
                return allowAmount == null ? null : allowAmount.getValue().toString();
            } catch (Exception e) {
                Log.e(TAG, "getContractAllowance--" + e.toString());
                return null;
            }
        }

        @Override
        public String exchangeToken(String networkUrl, String src,
                                    String dest, double amount, String walletAddress,
                                    String maxReceiveAmount,
                                    String minConversionRate, String password, double gasPrice,
                                    long gasLimit) {
            if (null == networkUrl || networkUrl.isEmpty()) {
                networkUrl = WalletManager.MAINNET_URL;
            }
            if (DEBUG) {
                Log.d(TAG, "exchangeToken----" + networkUrl);
            }
            try {
                Web3j web3j = Web3jFactory.build(new HttpService(networkUrl));
                WalletData wallet = getWalletDataByAddress(walletAddress);
                if (null == wallet || null == wallet.keyPath || wallet.keyStore.isEmpty()) {
                    Log.d(TAG, "wallet " + walletAddress + " not exist.");
                    return null;
                }
                Credentials credentials = null;
                try {
                    ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
                    WalletFile walletFile = objectMapper.readValue(wallet.keyStore, WalletFile.class);
                    credentials = Credentials.create(Wallet.decrypt(password, walletFile));
                } catch (Exception e) {
                    Log.d(TAG, "exchangeToken--Error: password is wrong!");
                    return null;
                }

                String kyberContractAddress = WalletManager.KYBER_MAIN_NETWORK_ADDRESS;
                if (networkUrl.equals(WalletManager.ROPSTEN_TEST_URL)) {
                    kyberContractAddress = WalletManager.KYBER_ROPSTEN_NETWORK_ADDRESS;
                }

                Function function = new Function(
                        "trade",
                        Arrays.<Type>asList(new Address(src),
                                new Uint256(BigDecimal.valueOf(amount).multiply(new BigDecimal(Math.pow(10, 18))).toBigInteger()),
                                new Address(dest),
                                new Address(walletAddress),
                                new Uint256(new BigInteger(maxReceiveAmount)),
                                new Uint256(new BigInteger(minConversionRate)),
                                new Address("0x0000000000000000000000000000000000000000")),
                        Collections.<TypeReference<?>>emptyList());
                String encodedFunction = FunctionEncoder.encode(function);

                // if send ERC20 Token ,the send values is ZERO
                BigInteger sendValue = BigDecimal.valueOf(amount).multiply(new BigDecimal(Math.pow(10, 18))).toBigInteger();
                if (!KYBER_NETWORK_ETH_ADDRESS.equals(src)) {
                    sendValue = BigInteger.ZERO;
                }
                RawTransactionManager txManager = new RawTransactionManager(web3j, credentials);
                EthSendTransaction transactionResponse = txManager.sendTransaction(
                        Convert.toWei(BigDecimal.valueOf(gasPrice), Convert.Unit.GWEI).toBigIntegerExact(),
                        BigInteger.valueOf(gasLimit), kyberContractAddress, encodedFunction, sendValue);

                if (transactionResponse.hasError()) {
                    Log.e(TAG, "exchangeToken--Error processing transaction request: "
                            + transactionResponse.getError().getMessage());
                    return null;
                }
                return transactionResponse.getTransactionHash();
            } catch (Exception e) {
                Log.e(TAG, "exchangeToken--" + e.toString());
                return null;
            }
        }

        @Override
        public String transferEthereum(String networkUrl, String accountAddress, String tokenAddress, String password,
                                   String destinationAddress, double amount,
                                   double gasPrice, long gasLimit, String remark) {

            if (null == networkUrl || networkUrl.isEmpty()) {
                networkUrl = WalletManager.MAINNET_URL;
            }
            if (DEBUG) {
                Log.d(TAG, "transferEthereum----" + networkUrl);
            }
            if (!isValidAddress(accountAddress, WALLET_CHAIN_TYPE_ETH)
                    || !isValidAddress(destinationAddress, WALLET_CHAIN_TYPE_ETH)) {
                Log.d(TAG, "transferEthereum----invalid address.");
                return null;
            }
            Web3j web3 = Web3jFactory.build(new HttpService(networkUrl));
            Credentials credentials = null;
            // check account address and password
            WalletData walletData = mWalletsMap.get(accountAddress);
            if (null == walletData) {
                Log.d(TAG, "Error: account address does not exist!");
                return null;
            }
            if (!isValidAddress(destinationAddress, WALLET_CHAIN_TYPE_ETH)) {
                Log.d(TAG, "Error: receiver's address is not valid, please check!");
                return null;
            }
            try {
                ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
                WalletFile walletFile = objectMapper.readValue(walletData.keyStore, WalletFile.class);
                credentials = Credentials.create(Wallet.decrypt(password, walletFile));
                if (DEBUG) {
                    Log.d(TAG, "load credential success");
                }
            } catch (Exception e) {
                Log.d(TAG, "Error: password is wrong!");
                return null;
            }
            if (null == credentials) {
                Log.d(TAG, "Error: password is wrong!");
                return null;
            }

            try {
                BigDecimal gasPriceWei = Convert.toWei(BigDecimal.valueOf(gasPrice), Convert.Unit.GWEI);
                RawTransactionManager txManager = new RawTransactionManager(web3, credentials);
                if (null == tokenAddress || tokenAddress.isEmpty()) {//means ethereum
                    EthSendTransaction transactionResponse =
                            txManager.sendTransaction(
                                    gasPriceWei.toBigIntegerExact(),
                                    BigInteger.valueOf(gasLimit),
                                    destinationAddress,
                                    Numeric.toHexString(remark.getBytes()),
                                    Convert.toWei(BigDecimal.valueOf(amount), Convert.Unit.ETHER).toBigInteger());
                    if (transactionResponse.hasError()) {
                        Log.e(TAG, "Error processing transaction request: "
                                + transactionResponse.getError().getMessage());
                        return null;
                    }

                    if (DEBUG) {
                        Log.d(TAG, "remark: " + remark + "; hex remark:"
                                + Numeric.toHexString(remark.getBytes()));
                    }

                    String transactionHash = transactionResponse.getTransactionHash();
                    return transactionHash;
                } else {//means token
                    Function function = new Function(
                            "transfer",
                            Arrays.<Type>asList(new Address(destinationAddress),
                                    new Uint256(BigDecimal.valueOf(amount).multiply(new BigDecimal(Math.pow(10, 18))).toBigInteger())),
                            Collections.<TypeReference<?>>emptyList());

                    EthSendTransaction transactionResponse =
                            txManager.sendTransaction(
                                    gasPriceWei.toBigIntegerExact(),
                                    BigInteger.valueOf(gasLimit),
                                    tokenAddress,
                                    FunctionEncoder.encode(function),
                                    BigInteger.ZERO);

                    if (transactionResponse.hasError()) {
                        Log.e(TAG, "Error processing transaction request: "
                                + transactionResponse.getError().getMessage());
                        return null;
                    }
                    return transactionResponse.getTransactionHash();
                }
            } catch (IOException | NumberFormatException e) {
                Log.e(TAG, "" + e.toString());
            }
            return null;
        }

        @Override
        public String getEthereumTransactionByHash(String networkUrl, String transactionHash) {
            if (null == networkUrl || networkUrl.isEmpty()) {
                networkUrl = WalletManager.MAINNET_URL;
            }
            if (DEBUG) {
                Log.d(TAG, "getEthereumTransactionByHash----" + networkUrl);
            }
            if (null == transactionHash || transactionHash.isEmpty()) {
                Log.d(TAG, "getEthereumTransactionByHash----invalid hash: " + transactionHash);
                return null;
            }
            String result = null;
            try {
                Web3j web3 = Web3jFactory.build(new HttpService(networkUrl));
                Request<?, EthTransaction> etr = web3.ethGetTransactionByHash(transactionHash);
                EthTransaction etx = etr.send();
                ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
                org.web3j.protocol.core.methods.response.Transaction trans = etx
                        .getTransaction();
                result = objectMapper.writeValueAsString(trans);
                return result;
            } catch (Exception e) {
                Log.e(TAG, "Failed to get transactionHash: " + e.toString());
            }
            return result;
        }

        @Override
        public long getBitcoinBalance(String address) {
            WalletData data = mWalletsMap.get(address);
            if (data != null && data.kitFileName != null) {
                WalletAppKit kit = mBTCWalletKits.get(data.kitFileName);
                if (kit != null && kit.wallet() != null) {
                    return kit.wallet().getBalance().getValue();// The number of satoshis of this monetary value.
                } else {
                    Log.e(TAG, "Can not find wallet for this kit.");
                }
            } else {
                Log.e(TAG, address + "address error.");
            }
            return -1;
        }

        @Override
        public String transferBitcoin(String address, String receiveAddress, String password,
                                      double amount, long fee, String remark) {
            try {
                WalletData data = mWalletsMap.get(address);
                if (data != null && data.mnemonicStr != null) {
                    // decrypt mnemonic string to verify password
                    if (!isValidMnemonic(data.mnemonicStr, password)) {
                        Log.e(TAG, "Failed to transfer bitcoin to " + receiveAddress + "! Password is wrong.");
                        return null;
                    }

                    WalletAppKit kit = mBTCWalletKits.get(data.kitFileName);
                    if (kit != null && kit.wallet() != null) {
                        // convert amount from BTC to Satoshi.
                        Coin value = Coin.valueOf(BigDecimal.valueOf(amount).multiply(
                                new BigDecimal(Math.pow(10, 8))).toBigInteger().longValue());
                        org.bitcoinj.core.Address to = org.bitcoinj.core.Address.fromBase58(
                                getNetworkParams(), receiveAddress);
                        org.bitcoinj.core.Transaction transaction =
                                new org.bitcoinj.core.Transaction(getNetworkParams());
                        transaction.addOutput(value, to);

                        SendRequest request = SendRequest.forTx(transaction);
                        // convert fee from Satoshi per byte to BTC per byte.
                        long feePerKb = new BigDecimal(fee).multiply(new BigDecimal(
                                WalletManager.BYTES_PER_BTC_KB)).longValue();

                        request.feePerKb = Coin.valueOf(feePerKb);

                        SendResult sendResult =
                                kit.wallet().sendCoins(kit.peerGroup(), request);
                        ListeningExecutorService executorService =
                                MoreExecutors.listeningDecorator(Executors.newCachedThreadPool());

                        sendResult.broadcastComplete.addListener(new Runnable() {
                            @Override
                            public void run() {
                                // The wallet has changed now, it'll get auto saved shortly or when the app shuts down.
                                Intent i = new Intent(BrahmaIntent.ACTION_TRANSACTION_BROADCAST_COMPLETE);
                                i.putExtra(BrahmaIntent.EXTRA_TRANSACTION_HASH, sendResult.tx.getHashAsString());
                                mContext.sendBroadcastAsUser(i, UserHandle.ALL);
                            }
                        }, executorService);
                        return sendResult.tx.getHashAsString();
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "transferBitcoin: " + e.toString());
            }
            return null;
        }

        @Override
        public List<TransactionDetails> getBitcoinTransactionsByTime(String address) {
            if (DEBUG) {
                Log.d(TAG, "getBitcoinTransactionsByTime for " + address);
            }
            WalletAppKit kit = getBitcoinWalletAppKit(address);
            if (null == kit || null == kit.wallet()) {
                Log.d(TAG, "getBitcoinTransactionsByTime----WalletAppKit not exist for " + address);
                return null;
            }
            List<org.bitcoinj.core.Transaction> txList = kit.wallet().getTransactionsByTime();
            if (null == txList || txList.size() <= 0) {
                Log.d(TAG, "getBitcoinTransactionsByTime----has no transactions for " + address);
                return null;
            }
            List<TransactionDetails> txDetailsList = new ArrayList<>();
            for (org.bitcoinj.core.Transaction transaction : txList) {
                try {
                    TransactionDetails txDetails = new TransactionDetails();
                    txDetails.hash = transaction.getHashAsString();
                    txDetails.amount = transaction.getValue(kit.wallet()).value;
                    txDetails.updateTime = transaction.getUpdateTime().getTime();
                    txDetails.depthInBlocks = transaction.getConfidence().getDepthInBlocks();
                    txDetails.confirmBlockHeight = transaction.getConfidence().getAppearedAtChainHeight();
                    txDetails.fee = transaction.getFee() == null ? 0 : transaction.getFee().value;
                    txDetails.bytesLength = transaction.unsafeBitcoinSerialize().length;
                    txDetails.inputs = new ArrayList<>();
                    txDetails.outputs = new ArrayList<>();

                    List<TransactionInput> inputList = transaction.getInputs();
                    if (inputList != null && inputList.size() > 0) {
                        for (TransactionInput input : inputList) {
                            try {
                                //get input address and amount
                                byte[] bytes = input.getScriptSig().getPubKey();
                                if (null == bytes) {
                                    continue;
                                }
                                org.bitcoinj.core.Address inputAddr = new org.bitcoinj.core.Address(getNetworkParams(),
                                        Utils.sha256hash160(bytes));
                                Coin inputValue = input.getValue();
                                if (inputAddr != null && inputValue != null) {
                                    HashMap<String, Long> map = new HashMap<>();
                                    map.put(inputAddr.toBase58(), inputValue.value);
                                    txDetails.inputs.add(map);
                                }
                            } catch (ScriptException | IllegalStateException | NullPointerException e) {
                                Log.e(TAG, "getBitcoinTransactionsByTime input error: " + e.toString());
                            }
                        }
                    }

                    List<TransactionOutput> outputList = transaction.getOutputs();
                    if (outputList != null && outputList.size() > 0) {
                        for (TransactionOutput output : outputList) {
                            try {
                                org.bitcoinj.core.Address outputAddr = output.getAddressFromP2PKHScript(getNetworkParams());
                                Coin outputValue = output.getValue();
                                if (outputAddr != null && outputValue != null) {
                                    HashMap<String, Long> map = new HashMap<>();
                                    map.put(outputAddr.toBase58(), outputValue.value);
                                    txDetails.outputs.add(map);
                                }
                            } catch (ScriptException | IllegalStateException | NullPointerException e) {
                                Log.e(TAG, "getBitcoinTransactionsByTime  output error: " + e.toString());
                            }
                        }
                    }
                    txDetailsList.add(txDetails);
                } catch (Exception e) {
                    Log.e(TAG, "getBitcoinTransactionsByTime error: " + e.toString());
                }
            }
            return txDetailsList;
        }

    };

    /** ===============================
     *      ETH functions begin
     * ================================ */
    /**
     * This is used to import ETH wallet by private key
     **/
    private WalletData generateETHWalletByPrivateKey(String name, String privateKey, String password) {
        if (!WalletUtils.isValidPrivateKey(privateKey)){
            return null;
        }
        WalletData walletData = new WalletData();
        walletData.name = name;
        walletData.avatar = null;
        walletData.isDefault = false;
        walletData.keyPath = BrahmaConstants.BIP_ETH_PATH;

        long creationTimeSeconds = System.currentTimeMillis() / 1000;
        walletData.createTime = creationTimeSeconds;
        walletData.lastUpdateTime = creationTimeSeconds;

        try {
            ECKeyPair ecKeyPair = ECKeyPair.create(Hex.decode(privateKey));

            if (ecKeyPair != null) {
                WalletFile walletFile = Wallet.createLight(password, ecKeyPair);
                // get wallet address
                walletData.address = Numeric.prependHexPrefix(walletFile.getAddress());
                // get keystore string
                ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
                walletData.keyStore = objectMapper.writeValueAsString(walletFile);
            }
        } catch (CipherException | JsonProcessingException e) {
            Log.e(TAG, "createDefaultETHWallet fail: " + e.toString());
            return null;
        }

        return walletData;
    }

    /**
     * This is used to create/import ETH wallet by mnemonics
     **/
    private WalletData generateETHWalletByMnemonic(String name, String mnemonics, String password) {
        WalletData walletData = new WalletData();
        walletData.name = name;
        walletData.avatar = null;
        walletData.isDefault = false;
        walletData.keyPath = BrahmaConstants.BIP_ETH_PATH;

        long creationTimeSeconds = System.currentTimeMillis() / 1000;
        walletData.createTime = creationTimeSeconds;
        walletData.lastUpdateTime = creationTimeSeconds;

        // generate and record keystore for ETH
        BigInteger privateKey = generatePrivateKey(mnemonics, walletData.keyPath);
        if (null == privateKey) {
            return null;
        }
        try {
            ECKeyPair ecKeyPair = ECKeyPair.create(privateKey);

            if (ecKeyPair != null) {
                WalletFile walletFile = Wallet.createLight(password, ecKeyPair);
                // get wallet address
                walletData.address = Numeric.prependHexPrefix(walletFile.getAddress());
                // get keystore string
                ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
                walletData.keyStore = objectMapper.writeValueAsString(walletFile);
            }
        } catch (CipherException | JsonProcessingException e) {
            Log.e(TAG, "generateETHWalletByMnemonic fail: " + e.toString());
            return null;
        }

        return walletData;
    }

    /**
     * This is used to import ETH wallet by keyStore
     **/
    private WalletData generateETHWalletByKeyStore(String name, String keyStore, String password) {
        WalletData walletData = new WalletData();
        walletData.name = name;
        walletData.avatar = null;
        walletData.isDefault = false;
        walletData.keyPath = BrahmaConstants.BIP_ETH_PATH;

        long creationTimeSeconds = System.currentTimeMillis() / 1000;
        walletData.createTime = creationTimeSeconds;
        walletData.lastUpdateTime = creationTimeSeconds;
        walletData.keyStore = keyStore;

        try {
            ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
            WalletFile walletFile = objectMapper.readValue(keyStore, WalletFile.class);
            // check the keystore by password
            if (!isValidKeystore(walletFile, password)) {
                Log.d(TAG, "Fail to import Ethereum wallet by keyStore, " +
                        "keyStore or password or both are wrong.");
                return null;
            }
            String address = Numeric.prependHexPrefix(walletFile.getAddress());
            if (!WalletUtils.isValidAddress(address)) {
                Log.d(TAG, "Fail to get wallet address by keyStore when importing Ethereum wallet");
                return null;
            }
            walletData.address = address;
        } catch (Exception e) {
            Log.d(TAG, "Fail to import Ethereum wallet by keyStore: " + e.toString());
            return null;
        }

        return walletData;
    }
    /** ===============================
     *      ETH functions end
     * ================================ */

    /** ===============================
     *      BTC functions begin
     * ================================ */
    /**
     * init all BTC WalletAppKit exist in brahma os
     **/
    private void initExistBTCWalletAppKit(String fileName) {
        if (DEBUG) {
            Log.d(TAG, "initExistBTCWalletAppKit--" + fileName);
        }
        WalletAppKit kit = new WalletAppKit(getNetworkParams(), mWalletDir, fileName) {
            @Override
            protected void onSetupCompleted() {
                // This is called in a background thread after startAndWait is called, as setting up various objects
                // can do disk and network IO that may cause UI jank/stuttering in wallet apps if it were to be done
                // on the main thread.
                Intent i = new Intent(BrahmaIntent.ACTION_WALLETAPPKIT_SETUP_COMPLETE);
                i.putExtra(BrahmaIntent.EXTRA_WALLET_FILE_NAME, fileName);
                mContext.sendBroadcastAsUser(i, UserHandle.ALL);
            }
        };
        kit.setDownloadListener(new MyDownloadProgressTracker(fileName));

        kit.setBlockingStartup(false);
        kit.startAsync();
        kit.awaitRunning();
        kit.wallet().addTransactionConfidenceEventListener(txListener);
        synchronized (mKitLock) {
            mBTCWalletKits.put(fileName, kit);
        }
    }

    /**
     * Used to create or import BTC wallet by mnemonics.
     * @param isCreation true for creating, false for importing.
     **/
    private WalletData generateBTCWalletByMnemonic(String name, String mnemonics,
                                                   String password, boolean isCreation) {
        WalletData walletData = new WalletData();
        walletData.name = name;
        walletData.avatar = null;
        walletData.isDefault = false;
        /**record main path for BTC**/
        walletData.keyPath = BrahmaConstants.BIP_BTC_PATH;

        /** used to verify the password of BTC **/
        walletData.mnemonicStr = DataCryptoUtils.aes128Encrypt(mnemonics, password);
        try {
            long timeSeconds = System.currentTimeMillis() / 1000;
            DeterministicSeed seed = new DeterministicSeed(
                    mnemonics, null, "", 0);
            if (isCreation) {
                seed.setCreationTimeSeconds(timeSeconds);
                Log.d(TAG, "setCreationTimeSeconds--" + timeSeconds);
            }

            /** record the time of first creating this wallet in the phone, not the creation time of seed**/
            walletData.createTime = timeSeconds;
            walletData.lastUpdateTime = timeSeconds;
            walletData.kitFileName = walletData.mnemonicStr;

            WalletAppKit kit = createBTCWalletAppKit(walletData.kitFileName, seed);
            String address = kit.wallet().getActiveKeyChain().getIssuedReceiveKeys()
                    .get(0).toAddress(getNetworkParams()).toBase58();
            if (address != null && !address.isEmpty()) {

                /**record the main address of BTC**/
                walletData.address = address;

                synchronized (mKitLock) {
                    mBTCWalletKits.put(walletData.kitFileName, kit);
                }
            } else {//if can not get the wallet's address, then delete the WalletAppKit files.
                Log.e(TAG, "createBitcoinWallet Failed! BTC wallet's main address error: " + address);
                deleteBTCFiles(walletData.kitFileName);
                return null;
            }
        } catch (Exception e) {
            Log.d(TAG, "createBitcoinWallet " + e.toString());
            return null;
        }
        return walletData;
    }

    private void deleteBTCFiles(String fileName) {
        if (null == fileName || fileName.isEmpty()) {
            return;
        }
        try {
            File chainFile = new File(mWalletDir, fileName + ".spvchain");
            if (chainFile != null && chainFile.exists()) {
                chainFile.delete();
                if (DEBUG) {
                    Log.d(TAG, fileName + ".spvchain has been deleted.");
                }
            }
            File walletFile = new File(mWalletDir, fileName + ".wallet");
            if (walletFile != null && walletFile.exists()) {
                walletFile.delete();
                if (DEBUG) {
                    Log.d(TAG, fileName + ".wallet has been deleted.");
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "deleteBTCFiles " + fileName + " failed : " + e.toString());
        }
    }

    /**
     * generate BTC WalletAppKit when create or import BTC wallet
     **/
    private WalletAppKit createBTCWalletAppKit(String fileName, DeterministicSeed seed) {
        WalletAppKit kit = new WalletAppKit(getNetworkParams(), mWalletDir, fileName) {
            @Override
            protected void onSetupCompleted() {
                // This is called in a background thread after startAndWait is called, as setting up various objects
                // can do disk and network IO that may cause UI jank/stuttering in wallet apps if it were to be done
                // on the main thread.
                Intent i = new Intent(BrahmaIntent.ACTION_WALLETAPPKIT_SETUP_COMPLETE);
                i.putExtra(BrahmaIntent.EXTRA_WALLET_FILE_NAME, fileName);
                mContext.sendBroadcastAsUser(i, UserHandle.ALL);
            }
        };
        kit.restoreWalletFromSeed(seed);
        kit.setDownloadListener(new MyDownloadProgressTracker(fileName));

        // set checkpoints
        // InputStream ins = mContext.getResources().openRawResource(
        //         mContext.getResources().getIdentifier(CHECK_POINTS_NAME,
        //        "raw", mContext.getPackageName()));
        // kit.setCheckpoints(ins);

        kit.setBlockingStartup(false);
        kit.startAsync();
        kit.awaitRunning();//after this function it will wait until onSetupCompleted being called
        kit.wallet().addTransactionConfidenceEventListener(txListener);
        synchronized (mKitLock) {
            mBTCWalletKits.put(fileName, kit);
        }
        return kit;
    }

    private NetworkParameters getNetworkParams() {
        return MainNetParams.get();
//        return TestNet3Params.get();//for test only
    }

    private class MyDownloadProgressTracker extends DownloadProgressTracker {
        private String mWalletFileName;
        public MyDownloadProgressTracker(String fileName) {
            mWalletFileName = fileName;
        }

        @Override
        public void onChainDownloadStarted(Peer peer, int blocksLeft) {
            super.onChainDownloadStarted(peer, blocksLeft);
            Intent i = new Intent(BrahmaIntent.ACTION_CHAIN_DOWNLOAD_STARTED);
            i.putExtra(BrahmaIntent.EXTRA_WALLET_FILE_NAME, mWalletFileName);
            i.putExtra(BrahmaIntent.EXTRA_PEER, peer.toString());
            i.putExtra(BrahmaIntent.EXTRA_BLOCKS_LEFT, blocksLeft);
            mContext.sendBroadcastAsUser(i, UserHandle.ALL);
        }

        @Override
        protected void progress(double pct, int blocksSoFar, Date date) {
            Intent i = new Intent(BrahmaIntent.ACTION_CHAIN_DOWNLOAD_PROGRESS);
            i.putExtra(BrahmaIntent.EXTRA_WALLET_FILE_NAME, mWalletFileName);
            i.putExtra(BrahmaIntent.EXTRA_PCT, pct);
            i.putExtra(BrahmaIntent.EXTRA_BLOCKS_SO_FAR, blocksSoFar);
            i.putExtra(BrahmaIntent.EXTRA_DATE_STRING, Utils.dateTimeFormat(date));
            mContext.sendBroadcastAsUser(i, UserHandle.ALL);
        }

        /**
         * Called when download is initiated.
         *
         * @param blocks the number of blocks to download, estimated
         */
        protected void startDownload(int blocks) {
            Intent i = new Intent(BrahmaIntent.ACTION_START_DOWNLOAD);
            i.putExtra(BrahmaIntent.EXTRA_WALLET_FILE_NAME, mWalletFileName);
            i.putExtra(BrahmaIntent.EXTRA_BLOCKS, blocks);
            mContext.sendBroadcastAsUser(i, UserHandle.ALL);
        }

        /**
         * Called when we are done downloading the block chain.
         */
        protected void doneDownload() {
            Intent i = new Intent(BrahmaIntent.ACTION_DONE_DOWNLOAD);
            i.putExtra(BrahmaIntent.EXTRA_WALLET_FILE_NAME, mWalletFileName);
            mContext.sendBroadcastAsUser(i, UserHandle.ALL);
            synchronized (mDownloadedListLock) {
                if (!mBTCDownloaded.contains(mWalletFileName)) {
                    mBTCDownloaded.add(mWalletFileName);
                }
            }
        }
    }

    private TransactionConfidenceEventListener txListener = new TransactionConfidenceEventListener() {
        @Override
        public void onTransactionConfidenceChanged(org.bitcoinj.wallet.Wallet wallet, org.bitcoinj.core.Transaction tx) {
            // Only broadcast confirmations within 6 blocks.
            int depth = tx.getConfidence().getDepthInBlocks();
            if (depth <= WalletManager.MIN_CONFIRMATIONS) {
                Intent i = new Intent(BrahmaIntent.ACTION_TRANSACTION_CONFIDENCE_CHANGED);
                i.putExtra(BrahmaIntent.EXTRA_TRANSACTION_HASH, tx.getHashAsString());
                i.putExtra(BrahmaIntent.EXTRA_DEPTH_IN_BLOCKS, depth);
                mContext.sendBroadcastAsUser(i, UserHandle.ALL);
            }
        }
    };

    private boolean isValidMnemonic(String mnemonicStr, String password) {
        if (null == mnemonicStr || null == password) {
            return false;
        }
        String mnemonic = DataCryptoUtils.aes128Decrypt(mnemonicStr, password);
        if (null == mnemonic || mnemonic.isEmpty()) {
            return false;
        }
        List<String> mnemonicsCodes = Splitter.on(" ").splitToList(mnemonic);
        if (null == mnemonicsCodes || mnemonicsCodes.size() == 0 || mnemonicsCodes.size() % 3 > 0) {
            return false;
        }
        return true;
    }
    /** ===============================
     *      BTC functions end
     * ================================ */

    private String generateMnemonics() {
        String passphrase = "";
        SecureRandom secureRandom = new SecureRandom();
        long creationTimeSeconds = System.currentTimeMillis() / 1000;
        DeterministicSeed deterministicSeed = new DeterministicSeed(secureRandom, 128, passphrase, creationTimeSeconds);
        List<String> mnemonicCode = deterministicSeed.getMnemonicCode();

        if (mnemonicCode != null && mnemonicCode.size() > 0) {
            StringBuilder mnemonicStr = new StringBuilder();
            List<String> alreadRecord = new ArrayList<>();
            for (String mnemonic : mnemonicCode) {
                // Judge whether appear the same mnemonic word, if has, regenerate the mnemonics.
                if (alreadRecord.contains(mnemonic)) {
                    return generateMnemonics();
                }
                alreadRecord.add(mnemonic);

                mnemonicStr.append(mnemonic).append(" ");
            }
            return mnemonicStr.toString().trim();
        }
        return null;
    }

    /**
     * generate private key by the given mnemonics
     **/
    private BigInteger generatePrivateKey(String mnemonics, String path) {
        try {
            // produce private key by mnemonic for different keyPath
            long timeSeconds = System.currentTimeMillis() / 1000;
            DeterministicSeed seed = new DeterministicSeed(mnemonics.trim(), null, "", timeSeconds);
            DeterministicKeyChain chain = DeterministicKeyChain.builder().seed(seed).build();
            List<ChildNumber> keyPath = HDUtils.parsePath(path);
            DeterministicKey key = chain.getKeyByPath(keyPath, true);
            BigInteger privateKey = key.getPrivKey();
            return privateKey;
        } catch (UnreadableWalletException e) {
            Log.d(TAG, "" + e.toString());
        }
        return null;
    }

    private boolean isValidKeystore(WalletFile walletFile, String password)
            throws Exception {
        Credentials credentials = Credentials.create(Wallet.decrypt(password, walletFile));
        BigInteger privateKey = credentials.getEcKeyPair().getPrivateKey();
        return WalletUtils.isValidPrivateKey(privateKey.toString(16));
    }

    /**
     * Caches the list of wallet addresses in an array, adjusting the array size when necessary.
     */
    private void updateWalletAddresses() {
        String[] walletAddressesToWrite = new String[mWalletsMap.size()];
        Iterator<Map.Entry<String, WalletData>> ir = mWalletsMap.entrySet().iterator();
        int i = 0;
        while (ir.hasNext()) {
            walletAddressesToWrite[i++] = ir.next().getKey();
        }
        mWalletAddresses = walletAddressesToWrite;
    }

    /**
     * @return true means the wallet name has not been used yet;
     *         false means the wallet name is empty or has been used in the wallet list.
     **/
    private boolean isValidWalletName(String name) {
        if (null == name || name.isEmpty()) {
            return false;
        }
        Iterator<Map.Entry<String, WalletData>> ir = mWalletsMap.entrySet().iterator();
        while (ir.hasNext()) {
            if (ir.next().getValue().name.equals(name)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Read wallet address list from /data/system/walletlist.xml if exist and then read wallet data
     *  form each wallet xml.
     *
     * This method should be called within the mLock
     **/
    private void readWalletListL() {
        if (!mWalletListFile.exists()) {
            if (DEBUG)
            {
                Log.d(TAG, "readWalletListL fail, "
                        + mWalletListFile.getAbsolutePath() + "not exist!");
            }
            return;
        }

        FileInputStream fis = null;
        AtomicFile userListFile = new AtomicFile(mWalletListFile);
        try {
            fis = userListFile.openRead();
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(fis, StandardCharsets.UTF_8.name());
            int type;
            while ((type = parser.next()) != XmlPullParser.START_TAG
                    && type != XmlPullParser.END_DOCUMENT) {
                // Skip
            }

            if (type != XmlPullParser.START_TAG) {
                Log.e(TAG, "Unable to read wallet list");
                return;
            }
            while ((type = parser.next()) != XmlPullParser.END_DOCUMENT) {
                if (type == XmlPullParser.START_TAG) {
                    final String name = parser.getName();
                    if (name.equals(TAG_WALLET)) {
                        String addr = parser.getAttributeValue(null, ATTR_ADDRESS);
                        if (DEBUG) {
                            Log.d(TAG, "readWalletListL get " + addr);
                        }
                        if (addr != null && !addr.isEmpty()) {
                            WalletData walletData = readWalletL(addr);
                            if (walletData != null) {
                                mWalletsMap.put(addr, walletData);
                                if (DEBUG) {
                                    Log.d(TAG, "readWalletListL kitFileName= "
                                            + walletData.kitFileName);
                                }
                                // init BTC WalletAppKit
                                if (walletData.keyPath != null && walletData.keyPath.startsWith(
                                        WalletManager.WALLET_CHAIN_TYPE_BTC)
                                        && walletData.kitFileName != null) {
                                    initExistBTCWalletAppKit(walletData.kitFileName);
                                }
                            }
                        }
                    }
                }
            }
            updateWalletAddresses();
        } catch (IOException | XmlPullParserException e) {
        } finally {
            IoUtils.closeQuietly(fis);
        }
    }

    /**
     * This method should be called within the mLock
     **/
    private WalletData readWalletL(String addr) {
        FileInputStream fis = null;
        try {
            AtomicFile walletFile = new AtomicFile(new File(mWalletDir, addr + XML_SUFFIX));
            if (DEBUG) {
                Log.d(TAG, "readWalletL file name: " + addr);
            }
            fis = walletFile.openRead();

            String address = addr;
            boolean isDefault = false;
            String keyPath = null;
            String privateKeyStr = null;
            String mnemonicStr = null;
            long createTime = 0;
            long lastUpdateTime = 0;
            String name = null;
            String avatar = null;
            String keyStore = null;
            String kitFileName = null;

            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(fis, StandardCharsets.UTF_8.name());
            int type;
            while ((type = parser.next()) != XmlPullParser.START_TAG
                    && type != XmlPullParser.END_DOCUMENT) {
                // Skip
            }

            if (type != XmlPullParser.START_TAG) {
                Log.e(TAG, "readWalletL, unable to read wallet data.");
                return null;
            }

            if (type == XmlPullParser.START_TAG && parser.getName().equals(TAG_WALLET)) {
                String storedAddr = parser.getAttributeValue(null, ATTR_ADDRESS);
                if (!address.equalsIgnoreCase(storedAddr)) {
                    Log.d(TAG, "readWalletL, wallet address does not match the file name.");
                    return null;
                }
                isDefault = readBooleanAttribute(parser, ATTR_ISDEFAULT, false);
                keyPath = parser.getAttributeValue(null, ATTR_KEY_PATH);
                privateKeyStr = parser.getAttributeValue(null, ATTR_PRIVATEKEY_STR);
                mnemonicStr = parser.getAttributeValue(null, ATTR_MNEMONIC_STR);

                int outerDepth = parser.getDepth();
                while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                        && (type != XmlPullParser.END_TAG || parser.getDepth() > outerDepth)) {
                    if (type == XmlPullParser.END_TAG || type == XmlPullParser.TEXT) {
                        continue;
                    }
                    String tag = parser.getName();
                    if (TAG_CREATE_TIME.equals(tag)) {
                        type = parser.next();
                        if (type == XmlPullParser.TEXT) {
                            try {
                                createTime = Long.parseLong(parser.getText());
                            } catch (Exception e) {
                                Log.e(TAG, "readWalletL, createTime: " + e.toString());
                                createTime = 0;
                            }
                        }
                    } else if (TAG_LAST_UPDATE_TIME.equals(tag)) {
                        type = parser.next();
                        if (type == XmlPullParser.TEXT) {
                            try {
                                lastUpdateTime = Long.parseLong(parser.getText());
                            } catch (Exception e) {
                                Log.e(TAG, "readWalletL, lastUpdateTime: " + e.toString());
                                lastUpdateTime = 0;
                            }
                        }
                    } else if (TAG_NAME.equals(tag)) {
                        type = parser.next();
                        if (type == XmlPullParser.TEXT) {
                            name = parser.getText();
                        }
                    } else if (TAG_AVATAR_PATH.equals(tag)) {
                        type = parser.next();
                        if (type == XmlPullParser.TEXT) {
                            avatar = parser.getText();
                        }
                    } else if (TAG_KEYSTORE.equals(tag)) {
                        type = parser.next();
                        if (type == XmlPullParser.TEXT) {
                            keyStore = parser.getText();
                        }
                    } else if (TAG_KIT_FILE_NAME.equals(tag)) {
                        type = parser.next();
                        if (type == XmlPullParser.TEXT) {
                            kitFileName = parser.getText();
                        }
                    }
                }
                WalletData walletData = new WalletData();
                walletData.createTime = createTime;
                walletData.lastUpdateTime = lastUpdateTime;
                walletData.name = name;
                walletData.avatar = avatar;
                walletData.isDefault = isDefault;
                walletData.keyPath = keyPath;
                walletData.address = address;
                walletData.keyStore = keyStore;
                walletData.privateKeyStr = privateKeyStr;
                walletData.mnemonicStr = mnemonicStr;
                walletData.kitFileName = kitFileName;
                return walletData;
            }
        } catch (IOException ioe) {
            Log.e(TAG, "Error reading wallet data xml for " + addr + ": " + ioe.toString());
        } catch (XmlPullParserException pe) {
            Log.e(TAG, "Error reading wallet data xml for " + addr + ": " + pe.toString());
        } catch (Exception e) {
            Log.e(TAG, "Error reading wallet data xml for " + addr + ": " + e.toString());
        } finally {
            IoUtils.closeQuietly(fis);
        }
        return null;
    }

    /**
     * This method should be called within the mLock
     **/
    private void writeWalletListL() {
        if (DEBUG) {
            Log.d(TAG, "writeWalletList");
        }
        FileOutputStream fos = null;
        AtomicFile walletListFile = new AtomicFile(mWalletListFile);
        try {
            fos = walletListFile.startWrite();
            final BufferedOutputStream bos = new BufferedOutputStream(fos);

            final XmlSerializer serializer = new FastXmlSerializer();
            serializer.setOutput(bos, StandardCharsets.UTF_8.name());
            serializer.startDocument(null, true);
            serializer.setFeature("http://xmlpull.org/v1/doc/features.html#indent-output", true);

            String[] walletAddressesToWrite = new String[mWalletsMap.size()];
            Iterator<Map.Entry<String, WalletData>> ir = mWalletsMap.entrySet().iterator();
            int i = 0;
            while (ir.hasNext()) {
                walletAddressesToWrite[i++] = ir.next().getKey();
            }

            serializer.startTag(null, TAG_WALLETS);
            for (String addr : walletAddressesToWrite) {
                if (addr != null && !addr.isEmpty()) {
                    serializer.startTag(null, TAG_WALLET);
                    serializer.attribute(null, ATTR_ADDRESS, addr);
                    serializer.endTag(null, TAG_WALLET);
                }
            }

            serializer.endTag(null, TAG_WALLETS);

            serializer.endDocument();
            walletListFile.finishWrite(fos);
        } catch (Exception e) {
            walletListFile.failWrite(fos);
            Log.e(TAG, "Error writing wallet list " + e.toString());
        }

    }

    /**
     * This method should be called within the mLock
     **/
    private void writeWalletL(WalletData walletData) {
        if (DEBUG) {
            Log.d(TAG, "writeWalletL " + walletData.address);
        }
        if (null == walletData || null == walletData.address || walletData.address.isEmpty()) {
            return;
        }
        FileOutputStream fos = null;
        AtomicFile walletFile = new AtomicFile(new File(mWalletDir, walletData.address + XML_SUFFIX));
        try {
            fos = walletFile.startWrite();
            final BufferedOutputStream bos = new BufferedOutputStream(fos);
            writeWalletL(walletData, bos);
            walletFile.finishWrite(fos);
        } catch (Exception ioe) {
            Log.e(TAG, "Error writing wallet data ", ioe);
            walletFile.failWrite(fos);
        }
    }

    /**
     * This method should be called within the mLock
     **/
    private void writeWalletL(WalletData walletData, OutputStream os)
            throws IOException, XmlPullParserException {
        if (null == walletData || null == walletData.address || walletData.address.isEmpty()) {
            return;
        }
        final XmlSerializer serializer = new FastXmlSerializer();
        serializer.setOutput(os, StandardCharsets.UTF_8.name());
        serializer.startDocument(null, true);
        serializer.setFeature("http://xmlpull.org/v1/doc/features.html#indent-output", true);

        serializer.startTag(null, TAG_WALLET);
        serializer.attribute(null, ATTR_ADDRESS, walletData.address);
        serializer.attribute(null, ATTR_ISDEFAULT, walletData.isDefault?"true":"false");
        serializer.attribute(null, ATTR_KEY_PATH, walletData.keyPath);
        if (walletData.privateKeyStr != null) {
            serializer.attribute(null, ATTR_PRIVATEKEY_STR, walletData.privateKeyStr);
        }
        if (walletData.mnemonicStr != null) {
            serializer.attribute(null, ATTR_MNEMONIC_STR, walletData.mnemonicStr);
        }
        try {
            serializer.startTag(null, TAG_CREATE_TIME);
            serializer.text(String.valueOf(walletData.createTime));
            serializer.endTag(null, TAG_CREATE_TIME);
        } catch (Exception e) {
            Log.d(TAG, "fail to write createTime: " + e.toString());
        }

        try {
            serializer.startTag(null, TAG_LAST_UPDATE_TIME);
            serializer.text(String.valueOf(walletData.lastUpdateTime));
            serializer.endTag(null, TAG_LAST_UPDATE_TIME);
        } catch (Exception e) {
            Log.d(TAG, "fail to write lastUpdateTime: " + e.toString());
        }

        // tag name is a must
        serializer.startTag(null, TAG_NAME);
        serializer.text(walletData.name != null ? walletData.name : "");
        serializer.endTag(null, TAG_NAME);

        // tag avatar is a must
        serializer.startTag(null, TAG_AVATAR_PATH);
        serializer.text(walletData.avatar != null ? walletData.avatar : "");
        serializer.endTag(null, TAG_AVATAR_PATH);

        if (walletData.keyStore != null && !walletData.keyStore.isEmpty()) {
            serializer.startTag(null, TAG_KEYSTORE);
            serializer.text(walletData.keyStore);
            serializer.endTag(null, TAG_KEYSTORE);
        }

        if (walletData.kitFileName != null && !walletData.kitFileName.isEmpty()) {
            serializer.startTag(null, TAG_KIT_FILE_NAME);
            serializer.text(walletData.kitFileName);
            serializer.endTag(null, TAG_KIT_FILE_NAME);
        }

        serializer.endTag(null, TAG_WALLET);

        serializer.endDocument();
    }

    private int readIntAttribute(XmlPullParser parser, String attr, int defaultValue) {
        String valueString = parser.getAttributeValue(null, attr);
        if (valueString == null) return defaultValue;
        try {
            return Integer.parseInt(valueString);
        } catch (NumberFormatException nfe) {
            return defaultValue;
        }
    }

    private long readLongAttribute(XmlPullParser parser, String attr, long defaultValue) {
        String valueString = parser.getAttributeValue(null, attr);
        if (valueString == null) return defaultValue;
        try {
            return Long.parseLong(valueString);
        } catch (NumberFormatException nfe) {
            return defaultValue;
        }
    }
    private boolean readBooleanAttribute(XmlPullParser parser, String attr, boolean defaultValue) {
        String valueString = parser.getAttributeValue(null, attr);
        if (valueString == null) return defaultValue;
        try {
            return valueString.equalsIgnoreCase("true".trim())?true:false;
        } catch (NumberFormatException nfe) {
            return defaultValue;
        }
    }

    private boolean isValidPassword(String password) {
        if (null == password) {
            return false;
        }
        return password.length() > 5;
    }

    public IWalletManager.Stub getBinder() {
        return mBinderImpl;
    }
}
