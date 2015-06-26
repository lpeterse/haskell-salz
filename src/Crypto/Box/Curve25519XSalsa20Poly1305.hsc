module Crypto.Box.Curve25519XSalsa20Poly1305
  ( PublicKey ()
  , SecretKey ()
  , crypto_box
  ) where

import Data.ByteString as B

import Foreign.C.Types
import Foreign.Ptr
import Foreign.C.String

newtype PublicKey
      = PublicKey ByteString

newtype SecretKey
      = SecretKey ByteString


foreign import ccall unsafe "crypto_scalarmult"
  crypto_scalarmult             :: Ptr a -> Ptr b -> Ptr c -> CInt

foreign import ccall unsafe "crypto_scalarmult_bytes"
  crypto_scalarmult_bytes       :: CSize

foreign import ccall unsafe "crypto_scalarmult_scalarbytes"
  crypto_scalarmult_scalarbytes :: CSize

foreign import ccall unsafe "crypto_scalarmult_primitive"
  crypto_scalarmult_primitive   :: CString

foreign import ccall unsafe "crypto_box"
  crypto_box                    :: Ptr a -> Ptr a -> CULLong -> Ptr a -> Ptr a -> Ptr a -> CInt