{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- Programa principal
module Main (main) where

import qualified Network
import Options.Applicative

-- Comandos principales
data Command
  = Server ServerOpts
  | Client ClientOpts

-- Opciones del servidor
data ServerOpts = ServerOpts
  { serverHost :: String
  , serverPort :: String
  , serverOutput :: Maybe FilePath
  }

-- Opciones del cliente
data ClientOpts = ClientOpts
  { clientHost :: String
  , clientPort :: String
  , clientInput :: FilePath
  }

serverCommand :: Parser Command
serverCommand =
  fmap Server $
    ServerOpts
      <$> strOption
        ( long "host"
            <> short 'h'
            <> metavar "HOST"
            <> value "127.0.0.1"
            <> help "Dirección de escucha del servidor"
        )
      <*> strOption
        ( long "port"
            <> short 'p'
            <> metavar "PORT"
            <> value "8888"
            <> help "Puerto de escucha del servidor"
        )
      <*> optional
        ( strOption
            ( long "output"
                <> short 'o'
                <> metavar "FILE"
                <> help "Archivo donde guardar los datos recibidos"
            )
        )

-- Parser para el comando cliente
clientCommand :: Parser Command
clientCommand =
  fmap Client $
    ClientOpts
      <$> strOption
        ( long "host"
            <> short 'h'
            <> metavar "HOST"
            <> value "127.0.0.1"
            <> help "Dirección del servidor"
        )
      <*> strOption
        ( long "port"
            <> short 'p'
            <> metavar "PORT"
            <> value "8888"
            <> help "Puerto del servidor"
        )
      <*> strOption
        ( long "input"
            <> short 'i'
            <> metavar "FILE"
            <> help "Archivo a enviar al servidor"
        )

-- Parser de comandos con subcomandos
commandParser :: Parser Command
commandParser =
  subparser
    ( command
        "server"
        ( info
            serverCommand
            (progDesc "Ejecutar en modo servidor (espera conexiones)")
        )
        <> command
          "client"
          ( info
              clientCommand
              (progDesc "Ejecutar en modo cliente (conecta al servidor)")
          )
    )

-- Información del programa
opts :: ParserInfo Command
opts =
  info
    (commandParser <**> helper)
    ( fullDesc
        <> header "cripto-final - transferencia de archivos"
        <> footer
          "Ejemplos:\n\
          \  cripto-final server -h 0.0.0.0 -p 8888 -o recibido.txt\n\
          \  cripto-final client -h 192.168.1.100 -p 8888 -i archivo.txt"
    )

-- Main
main :: IO ()
main = do
  commandInfo <- execParser opts
  putStrLn "=========================================="
  putStrLn "   CRIPTO-FINAL - DES + Diffie-Hellman    "
  putStrLn "=========================================="
  putStrLn ""
  case commandInfo of
    Server serverOpts -> do
      putStrLn "[*] Modo: SERVIDOR"
      putStrLn $ "[*] Host: " ++ serverOpts.serverHost
      putStrLn $ "[*] Puerto: " ++ serverOpts.serverPort
      putStrLn $ case serverOpts.serverOutput of
        Just f ->
          "[*] Output file: '" ++ f ++ "'"
        Nothing -> "[*] Sin output file"
      Network.runServer
        serverOpts.serverHost
        serverOpts.serverPort
        serverOpts.serverOutput
    Client clientOpts -> do
      putStrLn "[*] Modo: CLIENTE"
      putStrLn $ "[*] Host: " ++ clientOpts.clientHost
      putStrLn $ "[*] Puerto: " ++ clientOpts.clientPort
      putStrLn $ "[*] Archivo de entrada: " ++ clientOpts.clientInput
      putStrLn ""
      Network.runClient
        clientOpts.clientHost
        clientOpts.clientPort
        clientOpts.clientInput
  putStrLn "\n[+] Operación finalizada"