module Crypto.Box.Curve25519XSalsa20Poly1305
  ( PublicKey
  , SecretKey
  , keypair
  , beforenm
  ) where

import Control.Exception

import Data.ByteString        as B
import Data.ByteString.Unsafe as B

import Foreign.C.Types
import Foreign.Ptr
import Foreign.C.String
import Foreign.Marshal.Alloc

import System.IO.Unsafe (unsafePerformIO)

newtype PublicKey
      = PublicKey ByteString
      deriving (Eq, Ord, Show)

newtype SecretKey
      = SecretKey ByteString
      deriving (Eq, Ord, Show)

newtype SharedKey
      = SharedKey ByteString
      deriving (Eq, Ord, Show)

keypair :: IO (SecretKey, PublicKey)
keypair = do
  s <- mask_ $ do
    ptr <- mallocBytes sLen
    B.unsafePackMallocCStringLen (ptr, sLen) `onException` free ptr
  p <- mask_ $ do
    ptr <- mallocBytes pLen
    B.unsafePackMallocCStringLen (ptr, pLen) `onException` free ptr
  _ <-  B.unsafeUseAsCString p $ \pPtr->
          B.unsafeUseAsCString s $ \sPtr->
            crypto_box_keypair pPtr sPtr
  return (SecretKey s, PublicKey p)
  where
    sLen = fromIntegral crypto_box_secretkeybytes
    pLen = fromIntegral crypto_box_publickeybytes

beforenm :: SecretKey -> PublicKey -> SharedKey
beforenm (SecretKey s) (PublicKey p) = unsafePerformIO $ do
  k <- mask_ $ do
    ptr <- mallocBytes kLen
    B.unsafePackMallocCStringLen (ptr, kLen) `onException` free ptr
  _ <-  B.unsafeUseAsCString k $ \kPtr->
          B.unsafeUseAsCString p $ \pPtr->
            B.unsafeUseAsCString s $ \sPtr->
              crypto_box_beforenm kPtr pPtr sPtr
  return (SharedKey k)
  where
    kLen = fromIntegral crypto_box_beforenmbytes

foreign import ccall unsafe "crypto_box_keypair"
  crypto_box_keypair           :: Ptr CChar -> Ptr CChar -> IO CInt

foreign import ccall unsafe "crypto_box_beforenm"
  crypto_box_beforenm          :: Ptr CChar -> Ptr CChar -> Ptr CChar -> IO CInt

foreign import ccall unsafe "crypto_box_easy_afternm"
  crypto_box_easy_afternm      :: Ptr CChar -> Ptr CChar -> Ptr CChar -> IO CInt

foreign import ccall unsafe "crypto_box_open_easy_afternm"
  crypto_box_open_easy_afternm :: Ptr CChar -> Ptr CChar -> Ptr CChar -> IO CInt

foreign import ccall unsafe "crypto_box_beforenmbytes"
  crypto_box_beforenmbytes     :: CSize

foreign import ccall unsafe "crypto_box_secretkeybytes"
  crypto_box_secretkeybytes    :: CSize

foreign import ccall unsafe "crypto_box_publickeybytes"
  crypto_box_publickeybytes    :: CSize
