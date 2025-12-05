{-# LANGUAGE BangPatterns #-}

module DiffieHellman
  ( DHParams (..)
  , DHPrivate
  , DHPublic
  , generateDHParams
  , generateKeyPair
  , computeSharedSecret
  )
where

import Data.Bits
import System.Random

data DHParams = DHParams
  { dhPrime :: !Integer
  , dhGenerator :: !Integer
  }
  deriving (Show, Eq)

type DHPrivate = Integer

type DHPublic = Integer

-- Primo seguro de 1024 bits (Oakley Group 2) para demostración segura
safePrime1024 :: Integer
safePrime1024 =
  0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF

generator :: Integer
generator = 2

-- Por ser demostración no se hace generación aleatoria de número primo, pues sería muy costoso e incierto
generateDHParams :: IO DHParams
generateDHParams = return $ DHParams safePrime1024 generator

-- | Exponenciación modular: (base ^ exponente) % modulo
modPow :: Integer -> Integer -> Integer -> Integer
modPow _ 0 _ = 1
modPow base expo modulus = go 1 base expo
  where
    go !acc !b !e
      | e == 0 = acc
      | testBit e 0 =
          go ((acc * b) `mod` modulus) ((b * b) `mod` modulus) (shiftR e 1)
      | otherwise = go acc ((b * b) `mod` modulus) (shiftR e 1)

-- | Genera par de claves (Privada, Pública)
generateKeyPair :: DHParams -> IO (DHPrivate, DHPublic)
generateKeyPair (DHParams p g) = do
  rng <- newStdGen
  -- Clave privada aleatoria en [2, p-2]
  let limit = p - 3
      randVal = abs (fst (random rng :: (Integer, StdGen)))
      privateKey = 2 + (randVal `mod` limit)
      publicKey = modPow g privateKey p
  return (privateKey, publicKey)

-- | Calcula el secreto compartido: (otherPublic ^ myPrivate) % p
computeSharedSecret :: DHParams -> DHPrivate -> DHPublic -> Integer
computeSharedSecret (DHParams p _) myPrivate otherPublic =
  modPow otherPublic myPrivate p