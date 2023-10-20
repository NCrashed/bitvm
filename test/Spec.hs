{-# LANGUAGE ExtendedDefaultRules #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

import BitVM (BitHash, C, Gate (..), bitHash, opBitCommitment)
import Control.Concurrent.Async (cancel)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Control.Lens ((^?))
import Control.Monad (void)
import Crypto.Hash (Digest, hash)
import Crypto.Hash.Algorithms (SHA256)
import Data.Aeson (Value)
import qualified Data.Aeson.Decoding as A
import Data.Aeson.Lens
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Haskoin (Address, Ctx, MAST (MASTLeaf, MASTBranch), PubKey (PubKey), Script (Script), ScriptOp, TaprootOutput (TaprootOutput, internalKey, mast), addrToText, btcRegTest, createContext, outputAddress, taprootScriptOutput, Tx (Tx), addressToScript, TxOut (TxOut), TxIn (TxIn), OutPoint (OutPoint), hexToTxHash, encodeTaprootWitness, TaprootWitness (ScriptPathSpend), ScriptPathData (..), taprootOutputKey, getMerkleProofs, PublicKey (PublicKey), marshal, pubKey, encodeHex, textToAddr, verifyScriptPathData, ScriptOutput (PayWitness), XOnlyPubKey (XOnlyPubKey), addressToOutput, Marshal (marshalGet, marshalPut))
import Shelly
import Test.Tasty
import Test.Tasty.HUnit (testCase, (@?=))
import qualified Data.Serialize as S 
import Control.Lens.Internal.CTypes (Word8)
import Debug.Trace (traceShow, traceShowId)
import Data.Serialize (runGetState)

default (T.Text)

testProgram :: C Bool -> C Bool -> Gate Bool Bool
testProgram = NandGate

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [properties, unitTests]

properties :: TestTree
properties = testGroup "Properties" []

unitTests :: TestTree
unitTests =
  testGroup
    "Unit tests"
    [ testCase "Bit commitment is spendable by hash1 preimage" $ prepareNode $ \ctx datadir -> do
        let (address, tree, pk) = makeLeafTapAddress ctx $ opBitCommitment (bitHashText "hash1") (bitHashText "hash0")
        let addressText = fromMaybe "address encoding" $ addrToText btcRegTest address
        liftIO $ putStrLn $ "Bit commitment address: " ++ T.unpack addressText
        txid <- regtestSendTo datadir addressText 1.0
        liftIO $ putStrLn $ "Locking transaction: " ++ T.unpack txid
        regtestGenerate datadir 6
        vout <- getTransactionVout datadir txid
        liftIO $ putStrLn $ "Output vout: " ++ show vout
        spendAddr <- regtestNewAddr datadir 
        liftIO $ putStrLn $ check ctx address pk tree
        let tx = makeSpendingTx ctx tree pk "hash1" txid vout spendAddr 0.9999
        let txhex = encodeHex (S.encode tx)
        liftIO $ putStrLn $ "Raw transaction: " ++ T.unpack txhex
        void $ regtestCli datadir ["decoderawtransaction", txhex]
        liftIO $ putStrLn "Sending spending transaction"
        void $ regtestCli datadir ["sendrawtransaction", txhex]
    ]

bitHashText :: T.Text -> BitHash
bitHashText = bitHash . T.encodeUtf8

-- Take a program, place it as immediate leaf in the MAST tree and add unspendable dummy public key
makeLeafTapAddress :: Ctx -> [ScriptOp] -> (Address, MAST, PubKey)
makeLeafTapAddress ctx ops = (address, tree, pubkey)
  where
    pubkey = makeUnspendable "unspendable"
    tree = MASTLeaf 0xc0 (Script ops)
    output =
      TaprootOutput
        { internalKey = pubkey,
          mast = Just tree
        }
    address = fromMaybe (error "tap program without address") $ outputAddress ctx $ taprootScriptOutput ctx output

makeUnspendable :: T.Text -> PubKey
makeUnspendable preimage = PubKey (h <> h) -- to make 64 bytes
  where
    h = sha256 preimage

sha256 :: T.Text -> ByteString
sha256 v = convert (hash (T.encodeUtf8 v) :: Digest SHA256)

makeSpendingTx :: Ctx -> MAST -> PubKey -> T.Text -> T.Text -> Int -> Address -> Double -> Tx
makeSpendingTx ctx tree pubkey preimage txid vout toaddr amount = traceShow ("Verify: " ++ show (verifyScriptPathData ctx theOutputKey scriptPathSpend)) $ Tx 1 [tapInput] [mainOutput] [traceShow ("Taproot stack size " ++ show (length tapProof)) tapProof] 0
  where 
    outPoint = OutPoint (fromMaybe (error "invalid txid") $ hexToTxHash txid) (fromIntegral vout)
    tapInput = TxIn outPoint "" 0
    mainOutput = TxOut (ceiling $ amount * 100000000) (S.encode $ addressToScript ctx toaddr)
    tapProof = init $ encodeTaprootWitness ctx $ ScriptPathSpend scriptPathSpend
    scriptPathSpend = ScriptPathData {
      annex = Nothing, 
      -- stack = [T.encodeUtf8 preimage],
      stack = [],
      script = s, 
      extIsOdd = odd $ keyParity ctx theOutputKey, 
      leafVersion = version,
      internalKey = pubkey, 
      control = BA.convert <$> proof
    }
    theOutput = TaprootOutput pubkey (Just tree)
    theOutputKey = taprootOutputKey ctx theOutput
    ((version, s, proof) : _) = traceShowId $ getMerkleProofs tree

check :: Ctx -> Address -> PubKey -> MAST -> [Char]
check ctx address ipubkey mast = T.unpack (encodeHex bs) ++ " == " ++ T.unpack (encodeHex (S.runPut (marshalPut ctx q1)))
  where 
    PayWitness _ bs = addressToOutput address 
    -- Right (q0 :: XOnlyPubKey) = traceShowId $ S.runGet (marshalGet ctx) bs
    q1 = XOnlyPubKey $ taprootOutputKey ctx (TaprootOutput ipubkey (Just mast))

keyParity :: Ctx -> PubKey -> Word8
keyParity ctx key =
  case BS.unpack . marshal ctx $ PublicKey key True of
    0x02 : _ -> 0x00
    _ -> 0x01

prepareNode :: (Ctx -> FilePath -> Sh ()) -> IO ()
prepareNode ma = shelly $ withTmpDir $ \datadir -> bracket_sh (spawnRegtest datadir) shutdownRegtest $ const $ do
  waitNodeLoaded datadir
  createDefaultWallet datadir
  regtestDefaultGenerate datadir
  ctx <- liftIO createContext
  ma ctx datadir
  where
    spawnRegtest datadir = asyncSh $ run_ "bitcoind" ["-regtest", "-fallbackfee=0.00001", rpcpassArg, datadirArg datadir]
    shutdownRegtest = liftIO . cancel

rpcpassArg :: T.Text
rpcpassArg = "-rpcpassword=123456"

datadirArg :: FilePath -> T.Text
datadirArg v = T.concat ["-datadir=", T.pack v]

regtestCli :: FilePath -> [T.Text] -> Sh T.Text
regtestCli datadir args = run "bitcoin-cli" ("-regtest" : rpcpassArg : datadirArg datadir : args)

waitNodeLoaded :: FilePath -> Sh ()
waitNodeLoaded datadir = do
  res <- regtestCli datadir ["getrpcinfo"]
  liftIO $ print res

createDefaultWallet :: FilePath -> Sh ()
createDefaultWallet datadir = void $ regtestCli datadir ["createwallet", "test"]

regtestGenerate :: FilePath -> Int -> Sh ()
regtestGenerate datadir n = do
  address <- regtestCli datadir ["getnewaddress"]
  void $ regtestCli datadir ["generatetoaddress", showt n, T.strip address]

regtestNewAddr :: FilePath -> Sh Address
regtestNewAddr datadir = do 
  address <- regtestCli datadir ["getnewaddress"]
  pure $ fromMaybe (error "failed to parse address") $ textToAddr btcRegTest $ T.strip address

regtestDefaultGenerate :: FilePath -> Sh ()
regtestDefaultGenerate datadir = regtestGenerate datadir 101

regtestSendTo :: FilePath -> T.Text -> Double -> Sh T.Text
regtestSendTo datadir addr amount = T.strip <$> regtestCli datadir ["sendtoaddress", addr, showt amount]

getTransaction :: FilePath -> T.Text -> Sh Value
getTransaction datadir txid = do
  out <- regtestCli datadir ["gettransaction", txid]
  A.throwDecodeStrict $ T.encodeUtf8 out

getTransactionVout :: FilePath -> T.Text -> Sh Int
getTransactionVout datadir txid = do
  info <- getTransaction datadir txid
  pure $ maybe (error "missing vout in output") fromIntegral $ info ^? key "details" . nth 0 . key "vout" . _Integer

showt :: (Show a) => a -> T.Text
showt = T.pack . show
