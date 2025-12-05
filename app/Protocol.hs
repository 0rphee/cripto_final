{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Protocol
  ( Message (..)
  , HandshakeMsg (..)
  , serializeMessage
  , deserializeMessage
  )
where

import qualified Data.Binary as Binary
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import GHC.Generics (Generic)

-- Mensajes específicos del Handshake
data HandshakeMsg
  = ClientHello {clientPublicKey :: Integer}
  | ServerHello {serverPublicKey :: Integer}
  deriving (Generic, Show)

instance Binary.Binary HandshakeMsg

-- Mensajes generales del protocolo
data Message
  = HandshakeMsgWrapper HandshakeMsg -- Envolvemos el handshake
  | EncryptedData ByteString -- Datos cifrados con DES
  | EndOfTransmission -- Indica fin de archivo
  deriving (Generic, Show)

instance Binary.Binary Message

-- Serialización
serializeMessage :: Message -> ByteString
serializeMessage = BL.toStrict . Binary.encode

-- Deserialización
deserializeMessage :: ByteString -> Either String Message
deserializeMessage bs =
  case Binary.decodeOrFail (BL.fromStrict bs) of
    Left (_, _, err) -> Left err
    Right (_, _, msg) -> Right msg