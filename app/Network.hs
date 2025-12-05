{-# LANGUAGE OverloadedStrings #-}

module Network
  ( runServer
  , runClient
  )
where

import Control.Exception (bracket)
import qualified DES
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Foldable (for_)
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as T
import qualified DiffieHellman as DH
import qualified Network.Socket as Socket
import qualified Network.Socket.ByteString as SocketBS
import qualified Protocol as P

-- ==========================================
-- Utilidades de Red (Framing)
-- ==========================================

-- Envia un mensaje precedido por su longitud (4 bytes)
sendMessage :: Socket.Socket -> P.Message -> IO ()
sendMessage sock msg = do
  let serialized = P.serializeMessage msg
  let len = BS.length serialized
  let header = intToBytes len
  SocketBS.sendAll sock (header `BS.append` serialized)

-- Recibe un mensaje leyendo primero su longitud
recvMessage :: Socket.Socket -> IO (Either String P.Message)
recvMessage sock = do
  header <- recvAll sock 4
  if BS.length header < 4
    then return $ Left "Conexión cerrada o error en header"
    else do
      let len = bytesToInt header
      payload <- recvAll sock len
      if BS.length payload < len
        then pure $ Left "Payload incompleto"
        else pure $ P.deserializeMessage payload

-- Recibe exactamente n bytes
recvAll :: Socket.Socket -> Int -> IO ByteString
recvAll sock n = go BS.empty
  where
    go acc
      | BS.length acc >= n = return acc
      | otherwise = do
          chunk <- SocketBS.recv sock (n - BS.length acc)

          if BS.null chunk
            then return acc -- Socket cerrado
            else go (acc `BS.append` chunk)

-- Conversiones para el header de longitud (Big Endian)
intToBytes :: Int -> ByteString
intToBytes n = BS.pack [b3, b2, b1, b0]
  where
    b0 = fromIntegral (n .&. 0xFF)
    b1 = fromIntegral ((n `shiftR` 8) .&. 0xFF)
    b2 = fromIntegral ((n `shiftR` 16) .&. 0xFF)
    b3 = fromIntegral ((n `shiftR` 24) .&. 0xFF)

bytesToInt :: ByteString -> Int
bytesToInt bs =
  let [b3, b2, b1, b0] = map fromIntegral $ BS.unpack bs
   in (b3 `shiftL` 24) .|. (b2 `shiftL` 16) .|. (b1 `shiftL` 8) .|. b0

-- ==========================================
-- Lógica del Servidor
-- ==========================================

runServer :: String -> String -> Maybe FilePath -> IO ()
runServer host port mOutputFile = Socket.withSocketsDo $ do
  addr <- resolve host port
  putStrLn $ "[*] Iniciando servidor en " ++ host ++ ":" ++ port

  bracket (open addr) Socket.close $ \sock -> do
    Socket.listen sock 1
    putStrLn "[*] Esperando cliente..."

    (conn, peer) <- Socket.accept sock
    putStrLn $ "[*] Conexión desde: " ++ show peer

    handleConnection conn mOutputFile
    Socket.close conn

handleConnection :: Socket.Socket -> Maybe FilePath -> IO ()
handleConnection conn mOutputFile = do
  -- 1. Generar claves DH del servidor
  putStrLn "[*] Generando parámetros Diffie-Hellman..."
  dhParams <- DH.generateDHParams
  (srvPriv, srvPub) <- DH.generateKeyPair dhParams

  -- 2. Esperar ClientHello
  msg <- recvMessage conn
  case msg of
    Right (P.HandshakeMsgWrapper (P.ClientHello cliPub)) -> do
      putStrLn "[*] ClientHello recibido."

      -- 3. Enviar ServerHello
      putStrLn "[*] Enviando ServerHello..."
      sendMessage conn (P.HandshakeMsgWrapper (P.ServerHello srvPub))

      -- 4. Calcular secreto compartido
      let secret = DH.computeSharedSecret dhParams srvPriv cliPub
      let desKey = integerToDESKey secret
      putStrLn $ "[*] Handshake completado. Secreto compartido establecido."

      -- 5. Recibir datos cifrados
      receiveLoop conn desKey BS.empty
    Right _ -> putStrLn "[!] Error: Se esperaba ClientHello"
    Left err -> putStrLn $ "[!] Error de red: " ++ err
  where
    receiveLoop sock key acc = do
      msg <- recvMessage sock
      case msg of
        Right (P.EncryptedData chunk) -> do
          putStrLn $
            "[*] Recibido bloque cifrado (" ++ show (BS.length chunk) ++ " bytes)"
          let decryptedChunk = DES.desDecrypt key chunk
          receiveLoop sock key (acc `BS.append` decryptedChunk)
        Right P.EndOfTransmission -> do
          putStrLn "[*] Fin de transmisión recibido."
          saveOutput acc
        Right _ -> putStrLn "[!] Mensaje inesperado durante transferencia."
        Left err -> putStrLn $ "[!] Error recibiendo datos: " ++ err
    saveOutput :: ByteString -> IO ()
    saveOutput content = do
      putStrLn "[*] Contenido descifrado:"
      case TE.decodeUtf8' content of
        Left (_) -> do
          putStrLn "[!] ATENCIÓN: El contenido descifrado NO es texto UTF-8 válido."
          putStrLn "[*] Se mostrarán solo los primeros 80 bytes como Bytes (raw):"
          C8.putStrLn (BS.take 80 content)
        Right (text) -> do
          putStrLn "[*] El contenido es texto UTF-8 válido. Mostrando:"
          T.putStrLn text
      for_ mOutputFile $ \path -> do
        BS.writeFile path content
        putStrLn $ "[*] Archivo guardado exitosamente en: " ++ path

-- ==========================================
-- Lógica del Cliente
-- ==========================================

runClient :: String -> String -> FilePath -> IO () -- Asumiendo que ClientOpts se exporta o define aquí, o pasa los campos
runClient host port inputPath = Socket.withSocketsDo $ do
  addr <- resolve host port

  bracket (openClient addr) Socket.close $ \sock -> do
    putStrLn $ "[*] Conectado a " ++ host ++ ":" ++ port

    -- 1. Generar claves DH del cliente
    dhParams <- DH.generateDHParams
    (cliPriv, cliPub) <- DH.generateKeyPair dhParams

    -- 2. Enviar ClientHello
    putStrLn "[*] Enviando ClientHello..."
    sendMessage sock (P.HandshakeMsgWrapper (P.ClientHello cliPub))

    -- 3. Esperar ServerHello
    msg <- recvMessage sock
    case msg of
      Right (P.HandshakeMsgWrapper (P.ServerHello srvPub)) -> do
        putStrLn "[*] ServerHello recibido."

        -- 4. Calcular secreto compartido y clave DES
        let secret = DH.computeSharedSecret dhParams cliPriv srvPub
        let desKey = integerToDESKey secret
        putStrLn "[*] Handshake completado. Iniciando transmisión cifrada..."

        -- 5. Leer, cifrar y enviar archivo
        content <- BS.readFile inputPath
        putStrLn $ "[*] Leyendo archivo (" ++ show (BS.length content) ++ " bytes)"

        let encrypted = DES.desEncrypt desKey content
        sendMessage sock (P.EncryptedData encrypted)
        sendMessage sock P.EndOfTransmission

        putStrLn "[*] Archivo enviado."
      Right _ -> putStrLn "[!] Error: Se esperaba ServerHello"
      Left err -> putStrLn $ "[!] Error de red: " ++ err

-- Helpers de conexión
resolve :: String -> String -> IO Socket.AddrInfo
resolve host port = do
  let hints = Socket.defaultHints {Socket.addrSocketType = Socket.Stream}
  head <$> Socket.getAddrInfo (Just hints) (Just host) (Just port)

open :: Socket.AddrInfo -> IO Socket.Socket
open addr = do
  sock <-
    Socket.socket
      (Socket.addrFamily addr)
      (Socket.addrSocketType addr)
      (Socket.addrProtocol addr)

  Socket.setSocketOption sock Socket.ReuseAddr 1
  Socket.bind sock (Socket.addrAddress addr)
  return sock

openClient :: Socket.AddrInfo -> IO Socket.Socket
openClient addr = do
  sock <-
    Socket.socket
      (Socket.addrFamily addr)
      (Socket.addrSocketType addr)
      (Socket.addrProtocol addr)
  Socket.connect sock (Socket.addrAddress addr)
  return sock

-- Convierte el Integer de DH a los bits necesarios para la clave DES
integerToDESKey :: Integer -> DES.DESKey
integerToDESKey n = DES.prepareKey (integerToBS n)
  where
    -- Tomamos los últimos 8 bytes del Integer para la clave DES
    integerToBS :: Integer -> ByteString
    integerToBS i = BS.pack $ reverse $ take 8 $ byteList i

    byteList 0 = []
    byteList i = fromIntegral (i .&. 0xFF) : byteList (i `shiftR` 8)
