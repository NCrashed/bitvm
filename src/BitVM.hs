{-# LANGUAGE GADTs #-}
module BitVM
    ( 
        Gate(..),
        C(..),
        BitHash,
        bitHash, 
        opBitCommitment,
    ) where

import Crypto.Hash (Digest, hash)
import Crypto.Hash.Algorithms (SHA256)
import Haskoin (ScriptOp (..), PushDataType (OPCODE))
import Data.ByteArray (convert)
import Data.ByteString (ByteString)

-- | Commited value with type 'a'
data C a = C

data Gate a b where 
  NandGate :: C Bool -> C Bool -> Gate Bool Bool
  -- Here goes other basic gates

-- | Hash for single bit commitment
type BitHash = Digest SHA256 

-- | Make bit commitment hash
bitHash :: ByteString -> BitHash
bitHash = hash 

-- | A concrete implementation for a 1-bit commitment. To unlock this script, the
-- prover has to reveal either the preimage of hash0 or of hash1. In this example execution,
-- the prover reveals hash1, and sets the bit’s value to “1”. We can have copies of this
-- commitment to enforce a specific value across different scripts.
opBitCommitment :: BitHash -> BitHash -> [ScriptOp]
opBitCommitment hash1 hash0 = [
    OP_IF
  , OP_HASH160
  , OP_PUSHDATA (convert hash1) OPCODE  
  , OP_EQUALVERIFY
  , OP_1
  , OP_ELSE
  , OP_HASH160
  , OP_PUSHDATA (convert hash0) OPCODE
  , OP_EQUALVERIFY
  , OP_0
  , OP_ENDIF
  ]