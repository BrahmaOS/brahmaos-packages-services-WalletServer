package com.android.server.wallet;

import brahmaos.app.IOnETHBlanceGetListener;
import brahmaos.app.IWalletManager;
import brahmaos.app.WalletManager;
import brahmaos.app.WalletManager.OnETHBlanceGetListener;
import brahmaos.content.WalletData;
import android.os.Bundle;
import android.os.Environment;
import android.os.PersistableBundle;
import android.os.RemoteException;
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
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDUtils;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.UnreadableWalletException;
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

import rx.Completable;
import rx.Observable;
import rx.Observer;
import rx.Subscriber;
import rx.android.schedulers.AndroidSchedulers;
import rx.schedulers.Schedulers;

import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;

public class WalletServiceImpl {
    private static final String TAG = "WalletServiceImpl";
    private static final boolean DEBUG = true;

    //define tags and attrs used in the xml
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

    private static final String WALLET_DATA_DIR = "system";
    //record wallet list and each wallet's address
    private static final String WALLET_LIST_FILENAME = "walletlist.xml";
    private static final String XML_SUFFIX = ".xml";

    private final File mWalletDir;
    private final File mWalletListFile;

    private DataCryptoUtils mDcUtils;
    private final WalletSystem.SyncRoot mLock;
    private HashMap<String, WalletData> mWalletsMap = new HashMap<>();//<address, WalletData>
    private String[] mWalletAddresses;

    public WalletServiceImpl(WalletSystem.SyncRoot lock) {
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
        @Override
        public WalletData createDefaultETHWallet(String name, String mnemonics, String password) {
            Log.d(TAG, "begin createDefaultETHWallet");

            WalletData walletData = generateETHWalletByMnemonic(name, mnemonics, password);
            if (null == walletData) {
                return null;
            }
            walletData.isDefault = true;
            synchronized (mLock) {
                mWalletsMap.put(walletData.address, walletData);
                writeWalletL(walletData);
                writeWalletListL();
            }
            return walletData;
        }

        @Override
        public List<WalletData> createWallet(String name, String password) {
            List<WalletData> wallets = new ArrayList<>();
            WalletData ethWallet = createEthereumWallet(name + "_ETH", password);
            if (ethWallet != null) {
                wallets.add(ethWallet);
            }
            return wallets;
        }

        @Override
        public WalletData createEthereumWallet(String name,String password) {
            Log.d(TAG, "begin createEthereumWallet");
            String mnemonics = generateMnemonics();
            if (null == mnemonics || mnemonics.isEmpty()) {
                return null;
            }
            WalletData walletData = generateETHWalletByMnemonic(name, mnemonics, password);
            if (null == walletData) {
                return null;
            }

            /**only store encrypted mnemonics string when creating new wallet**/
            walletData.mnemonicStr = mDcUtils.aes128Encrypt(mnemonics, password);

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
                Log.d(TAG, "The data must not be empty!");
                return null;
            }
            WalletData walletData;
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
            synchronized (mLock) {
                mWalletsMap.put(walletData.address, walletData);
                writeWalletL(walletData);
                writeWalletListL();
            }
            return walletData;
        }

        @Override
        public int deleteWalletByAddress(String address) {
            Log.d(TAG, "begin deleteWalletByAddress");
            WalletData needDeleteWallet = mWalletsMap.get(address);
            if (null == needDeleteWallet) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            if (needDeleteWallet.isDefault) {
                return WalletManager.CODE_DEFAULT_WALLET_CANNOT_DELETE;
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
            updateWalletAddresses();
            return WalletManager.CODE_NO_ERROR;
        }

        @Override
        public int updateWalletNameForAddress(String newName, String address) {
            Log.d(TAG, "begin updateWalletNameForAddress");
            WalletData walletData = mWalletsMap.get(address);
            if (null == walletData) {
                return WalletManager.CODE_WALLET_NOT_EXIST;
            }
            if (checkWalletNameExist(newName)) {
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
            Log.d(TAG, "begin updateWalletAvatarForAddress");
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
        public int updateEthereumWalletPassword(String address, String oldPassword, String newPassword) {
            Log.d(TAG, "begin updateEthereumWalletPassword");
            if (mWalletsMap.containsKey(address)) {
                WalletData needUpdateWalletData = mWalletsMap.get(address);
                try {
                    //Check the old password by the old keyStore
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

                        //if new WalletFile's address changed for Ethereum Wallet, return false
                        String addr = Numeric.prependHexPrefix(walletFile.getAddress());
                        if (!needUpdateWalletData.address.equalsIgnoreCase(addr)) {
                            Log.d(TAG, "has generated new address: " + addr);
                            return WalletManager.CODE_WALLET_EXCEPTION;
                        }

                        //get keystore string
                        needUpdateWalletData.keyStore = objectMapper.writeValueAsString(walletFile);
                        needUpdateWalletData.lastUpdateTime = System.currentTimeMillis() / 1000;
                    }
                } catch (Exception e) {
                    Log.e(TAG, "createDefaultETHWallet fail: " + e.toString());
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
                //keyPath is the full chain path, and chain type is the sub string
                // of keyPath from start to coin type
                if (tempData.keyPath.startsWith(chainType)) {
                    walletsForChainType.add(tempData);
                }
            }
            return walletsForChainType;
        }

        @Override
        public WalletData getWalletDataByAddress(String address) {
            return mWalletsMap.get(address);
        }

        public boolean isValidAddress(String address, String chainType) {
            if (WalletManager.WALLET_CHAIN_TYPE_ETH.equalsIgnoreCase(chainType)) {
                return address != null && address.length() >= 2 &&
                        address.charAt(0) == '0' && address.charAt(1) == 'x' &&
                        WalletUtils.isValidAddress(address);
            } else {
                return true;
            }
        }

        @Override
        public void getEthereumAccountBalanceByAddress(String networkUrl, String addr,
                                                       IOnETHBlanceGetListener listener) {
            if (DEBUG) {
                Log.d(TAG, "getEthereumAccountBalanceByAddress----" + networkUrl);
            }
            Web3j web3 = Web3jFactory.build(new HttpService(networkUrl));
            web3.ethGetBalance(addr, DefaultBlockParameterName.LATEST)
                    .observable()
                    .subscribeOn(Schedulers.io())
                    .observeOn(AndroidSchedulers.mainThread())
                    .subscribe(new Observer<EthGetBalance>() {
                        @Override
                        public void onCompleted() {
                        }

                        @Override
                        public void onError(Throwable e) {
                            if (DEBUG) {
                                Log.d(TAG, "ETH blance--" + e.toString());
                            }
                            try {
                                listener.onETHBlanceGetError();
                            } catch (RemoteException re) {
                                Log.e(TAG, "Error in onError: " + re.toString());
                            }
                        }

                        @Override
                        public void onNext(EthGetBalance ethBalance) {
                            try {
                                if (DEBUG) {
                                    Log.d(TAG, "ETH " + addr + ": " + ethBalance.getBalance());
                                }
                                if (ethBalance != null && ethBalance.getBalance() != null) {
                                    listener.onETHBlanceGetSuccess(ethBalance.getBalance().toString());
                                } else {
                                    listener.onETHBlanceGetSuccess("0");
                                }
                            } catch (RemoteException re) {
                                Log.e(TAG, "Error in onNext: " + re.toString());
                            }
                        }
                    });
        }

        @Override
        public void getEthereumTokenBalanceByAddress(String networkUrl, String addr,
                                                     String tokenAddr,
                                                     IOnETHBlanceGetListener listener) {
            if (DEBUG) {
                Log.d(TAG, "getEthereumTokenBalanceByAddress----" + networkUrl);
            }
            Web3j web3 = Web3jFactory.build(new HttpService(networkUrl));
            Function function = new Function(
                    "balanceOf",
                    Arrays.asList(new Address(addr)),  // Solidity Types in smart contract functions
                    Arrays.asList(new TypeReference<Uint256>() {
                    }));

            String encodedFunction = FunctionEncoder.encode(function);
            Transaction trans = Transaction.createEthCallTransaction(addr, tokenAddr, encodedFunction);

            try {
                EthCall ethCall = web3.ethCall(
                        trans,
                        DefaultBlockParameterName.LATEST).send();
                try {
                    if (ethCall != null && ethCall.getValue() != null) {
                        if (DEBUG) {
                            Log.d(TAG, tokenAddr + ": " + ethCall.getValue());
                        }
                        try {
                            listener.onETHBlanceGetSuccess(Numeric.decodeQuantity(ethCall.getValue()).toString());
                        } catch (Exception e) {
                            listener.onETHBlanceGetSuccess("0");
                        }
                    } else {
                        try {
                            listener.onETHBlanceGetError();
                        } catch (RemoteException re) {
                            Log.e(TAG, "Error in onError: " + re.toString());
                        }
                    }
                } catch (RemoteException re) {
                    Log.e(TAG, "Error in onNext: " + re.toString());
                }
            } catch (Exception e) {
                Log.e(TAG, "Error in ethCall: " + e.toString());
                try {
                    listener.onETHBlanceGetError();
                } catch (RemoteException re) {
                    Log.e(TAG, "Error in onError: " + re.toString());
                }
            }

            /*Request<?, EthCall> ethCall = web3.ethCall(
                    trans,
                    DefaultBlockParameterName.LATEST);
            ethCall.observable()
                    .subscribeOn(Schedulers.io())
                    .observeOn(AndroidSchedulers.mainThread())
                    .subscribe(new Observer<EthCall>() {
                        @Override
                        public void onCompleted() {
                        }

                        @Override
                        public void onError(Throwable e) {
                            if (DEBUG) {
                                Log.d(TAG, tokenAddr + " token blance--" + e.toString());
                            }
                            try {
                                listener.onETHBlanceGetError();
                            } catch (RemoteException re) {
                                Log.e(TAG, "Error in onError: " + re.toString());
                            }

                        }

                        @Override
                        public void onNext(EthCall ethCall) {
                            try {
                                if (ethCall != null && ethCall.getValue() != null) {
                                    if (DEBUG) {
                                        Log.d(TAG, tokenAddr + ": " + ethCall.getValue());
                                    }
                                    listener.onETHBlanceGetSuccess(Numeric.decodeQuantity(ethCall.getValue()).toString());
                                } else {
                                    listener.onETHBlanceGetSuccess("0");
                                }
                            } catch (RemoteException re) {
                                Log.e(TAG, "Error in onNext: " + re.toString());
                            }
                        }
                    });*/
        }

        @Override
        public String transferEthereum(String networkUrl, String accountAddress, String tokenAddress, String password,
                                   String destinationAddress, double amount,
                                   double gasPrice, long gasLimit, String remark) {
            if (DEBUG) {
                Log.d(TAG, "transferEthereum----" + networkUrl);
            }
            Web3j web3 = Web3jFactory.build(new HttpService(networkUrl));
            Credentials credentials = null;
            //check account address and password
            WalletData walletData = mWalletsMap.get(accountAddress);
            if (null == walletData) {
                Log.d(TAG, "Error: account address does not exist!");
                return null;
            }
            if (!isValidAddress(destinationAddress, WalletManager.WALLET_CHAIN_TYPE_ETH)) {
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
            if (DEBUG) {
                Log.d(TAG, "getEthereumTransactionByHash----" + networkUrl);
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
    };

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
                //get wallet address
                walletData.address = Numeric.prependHexPrefix(walletFile.getAddress());
                //get keystore string
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

        //get wallet private key
        BigInteger privateKey = generatePrivateKey(mnemonics, walletData.keyPath);
        if (null == privateKey) {
            return null;
        }
        try {
            ECKeyPair ecKeyPair = ECKeyPair.create(privateKey);

            if (ecKeyPair != null) {
                WalletFile walletFile = Wallet.createLight(password, ecKeyPair);
                //get wallet address
                walletData.address = Numeric.prependHexPrefix(walletFile.getAddress());
                //get keystore string
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
            //check the keystore by password
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
        } catch (Exception e) {
            Log.d(TAG, "Fail to import Ethereum wallet by keyStore: " + e.toString());
            return null;
        }

        return walletData;
    }

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
                //Judge whether appear the same mnemonic word, if has, regenerate the mnemonics
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
            //produce private key by mnemonic for different keyPath
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
        synchronized (mLock) {
            String[] walletAddressesToWrite = new String[mWalletsMap.size()];
            Iterator<Map.Entry<String, WalletData>> ir = mWalletsMap.entrySet().iterator();
            int i = 0;
            while (ir.hasNext()) {
                walletAddressesToWrite[i++] = ir.next().getKey();
            }
            mWalletAddresses = walletAddressesToWrite;
        }
    }

    /**
     * @return true means the wallet name has been used in the wallet list;
     *         false means the wallet name have not been used yet.
     **/
    private boolean checkWalletNameExist(String name) {
        Iterator<Map.Entry<String, WalletData>> ir = mWalletsMap.entrySet().iterator();
        while (ir.hasNext()) {
            if (ir.next().getValue().name.equals(name)) {
                return true;
            }
        }
        return false;
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
                                    Log.d(TAG, "readWalletListL mWalletsMap.put " + addr);
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
                Log.d(TAG, "addr=" + addr);
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
            Log.d(TAG, "writeUserL " + walletData.address);
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

        //tag name is must
        serializer.startTag(null, TAG_NAME);
        serializer.text(walletData.name != null ? walletData.name : "");
        serializer.endTag(null, TAG_NAME);

        //tag avatar is must
        serializer.startTag(null, TAG_AVATAR_PATH);
        serializer.text(walletData.avatar != null ? walletData.avatar : "");
        serializer.endTag(null, TAG_AVATAR_PATH);

        //tag keystore is must
        serializer.startTag(null, TAG_KEYSTORE);
        serializer.text(walletData.keyStore != null ? walletData.keyStore : "");
        serializer.endTag(null, TAG_KEYSTORE);

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


    public IWalletManager.Stub getBinder() {
        return mBinderImpl;
    }
}
