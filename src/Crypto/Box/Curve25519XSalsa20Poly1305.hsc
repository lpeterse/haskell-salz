module Crypto.Box.Curve25519XSalsa20Poly1305
  ( PublicKey
  , SecretKey
  , keypair
  , beforenm
  ) where

import Data.ByteString        as B
import Data.ByteString.Unsafe as B
import Data.SecureMem
import Data.Word

import Foreign.C.Types
import Foreign.Ptr
import Foreign.C.String

import System.IO.Unsafe (unsafePerformIO)

newtype PublicKey
      = PublicKey SecureMem
      deriving (Eq)

newtype SecretKey
      = SecretKey SecureMem
      deriving (Eq)

newtype SharedKey
      = SharedKey SecureMem
      deriving (Eq)

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
            withSecureMemPtr s $ \sPtr->
              crypto_box_beforenm kPtr pPtr sPtr
  return (SharedKey k)
  where
    kLen = fromIntegral crypto_box_beforenmbytes

foreign import ccall unsafe "crypto_box_keypair"
  crypto_box_keypair           :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_box_beforenm"
  crypto_box_beforenm          :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

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
