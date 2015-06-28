module Crypto.Box.Curve25519XSalsa20Poly1305
  ( PublicKey
  , SecretKey
  , keypair
  , beforenm
  , afternm
  ) where

import Control.Exception

import Crypto.Nonce as Nonce

import Data.ByteString        as B
import Data.ByteString.Unsafe as B
import Data.SecureMem
import Data.Word

import Foreign.C.Types
import Foreign.Ptr
import Foreign.C.String
import Foreign.Marshal.Alloc

import System.IO.Unsafe (unsafePerformIO)

newtype PublicKey
      = PublicKey SecureMem
      deriving (Eq, Show)

newtype SecretKey
      = SecretKey SecureMem
      deriving (Eq, Show)

newtype SharedKey
      = SharedKey SecureMem
      deriving (Eq, Show)

newtype Nonce
      = Nonce ByteString
      deriving (Eq, Show)

keypair :: IO (SecretKey, PublicKey)
keypair = do
  p <-  allocateSecureMem pLen
  s <-  allocateSecureMem sLen
  _ <-  withSecureMemPtr p $ \pPtr->
          withSecureMemPtr s $ \sPtr->
            crypto_box_keypair pPtr sPtr
  return (SecretKey s, PublicKey p)
  where
    sLen = fromIntegral crypto_box_secretkeybytes
    pLen = fromIntegral crypto_box_publickeybytes

beforenm :: SecretKey -> PublicKey -> SharedKey
beforenm (SecretKey s) (PublicKey p) = unsafePerformIO $ do
  k <-  allocateSecureMem kLen
  _ <-  withSecureMemPtr k $ \kPtr->
        withSecureMemPtr p $ \pPtr->
        withSecureMemPtr s $ \sPtr-> do
          crypto_box_beforenm kPtr pPtr sPtr
  return (SharedKey k)
  where
    kLen = fromIntegral crypto_box_beforenmbytes

afternm :: ByteString -> Nonce -> SharedKey -> IO ByteString
afternm m (Nonce n) (SharedKey k) = do
  c  <- mask_ $ do
    ptr <- mallocBytes cLen
    B.unsafePackMallocCStringLen (ptr, cLen) `onException` free ptr
  _  <- unsafeUseAsCString c $ \cPtr->
        unsafeUseAsCString m $ \mPtr->
        unsafeUseAsCString n $ \nPtr->
        withSecureMemPtr   k $ \kPtr-> do
          crypto_box_easy_afternm cPtr mPtr (fromIntegral mLen) nPtr kPtr
  return c
  where
    mLen = B.length m
    cLen = fromIntegral crypto_box_macbytes + mLen

foreign import ccall unsafe "crypto_box_keypair"
  crypto_box_keypair           :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_box_beforenm"
  crypto_box_beforenm          :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_box_easy_afternm"
  crypto_box_easy_afternm      :: Ptr CChar -> Ptr CChar -> CULLong -> Ptr CChar -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_box_open_easy_afternm"
  crypto_box_open_easy_afternm :: Ptr CChar -> Ptr CChar -> Ptr CChar -> IO CInt

foreign import ccall unsafe "crypto_box_beforenmbytes"
  crypto_box_beforenmbytes     :: CSize

foreign import ccall unsafe "crypto_box_secretkeybytes"
  crypto_box_secretkeybytes    :: CSize

foreign import ccall unsafe "crypto_box_publickeybytes"
  crypto_box_publickeybytes    :: CSize

foreign import ccall unsafe "crypto_box_macbytes"
  crypto_box_macbytes          :: CSize

foreign import ccall unsafe "crypto_box_noncebytes"
  crypto_box_noncebytes        :: CSize