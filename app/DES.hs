{-# LANGUAGE BangPatterns #-}

-- | Implementación completa del algoritmo DES (Data Encryption Standard)
-- Sin uso de librerías criptográficas externas
module DES
    ( desEncrypt
    , desDecrypt
    , prepareKey
    , DESKey
    ) where

import Data.Bits
import Data.Word
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

type DESKey = [Bool]

-- Tablas de permutación DES estándar

-- Permutación inicial (IP)
initialPermutation :: [Int]
initialPermutation = 
    [ 58, 50, 42, 34, 26, 18, 10, 2
    , 60, 52, 44, 36, 28, 20, 12, 4
    , 62, 54, 46, 38, 30, 22, 14, 6
    , 64, 56, 48, 40, 32, 24, 16, 8
    , 57, 49, 41, 33, 25, 17,  9, 1
    , 59, 51, 43, 35, 27, 19, 11, 3
    , 61, 53, 45, 37, 29, 21, 13, 5
    , 63, 55, 47, 39, 31, 23, 15, 7
    ]

-- Permutación final (IP^-1)
finalPermutation :: [Int]
finalPermutation = 
    [ 40, 8, 48, 16, 56, 24, 64, 32
    , 39, 7, 47, 15, 55, 23, 63, 31
    , 38, 6, 46, 14, 54, 22, 62, 30
    , 37, 5, 45, 13, 53, 21, 61, 29
    , 36, 4, 44, 12, 52, 20, 60, 28
    , 35, 3, 43, 11, 51, 19, 59, 27
    , 34, 2, 42, 10, 50, 18, 58, 26
    , 33, 1, 41,  9, 49, 17, 57, 25
    ]

-- Expansión E de 32 a 48 bits
expansionTable :: [Int]
expansionTable = 
    [ 32,  1,  2,  3,  4,  5
    ,  4,  5,  6,  7,  8,  9
    ,  8,  9, 10, 11, 12, 13
    , 12, 13, 14, 15, 16, 17
    , 16, 17, 18, 19, 20, 21
    , 20, 21, 22, 23, 24, 25
    , 24, 25, 26, 27, 28, 29
    , 28, 29, 30, 31, 32,  1
    ]

-- Permutación P después de las S-boxes
permutationTable :: [Int]
permutationTable = 
    [ 16,  7, 20, 21, 29, 12, 28, 17
    ,  1, 15, 23, 26,  5, 18, 31, 10
    ,  2,  8, 24, 14, 32, 27,  3,  9
    , 19, 13, 30,  6, 22, 11,  4, 25
    ]

-- S-Boxes (8 cajas de sustitución)
sBoxes :: [[[Int]]]
sBoxes = 
    [ -- S1
      [ [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]
      , [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8]
      , [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0]
      , [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
      ]
    , -- S2
      [ [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10]
      , [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5]
      , [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15]
      , [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
      ]
    , -- S3
      [ [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8]
      , [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1]
      , [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7]
      , [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
      ]
    , -- S4
      [ [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15]
      , [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9]
      , [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4]
      , [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
      ]
    , -- S5
      [ [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9]
      , [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6]
      , [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14]
      , [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
      ]
    , -- S6
      [ [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11]
      , [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8]
      , [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6]
      , [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
      ]
    , -- S7
      [ [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1]
      , [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6]
      , [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2]
      , [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
      ]
    , -- S8
      [ [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7]
      , [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2]
      , [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8]
      , [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
      ]
    ]

-- Permutación PC-1 para generación de claves (56 bits de 64)
pc1 :: [Int]
pc1 = 
    [ 57, 49, 41, 33, 25, 17,  9
    ,  1, 58, 50, 42, 34, 26, 18
    , 10,  2, 59, 51, 43, 35, 27
    , 19, 11,  3, 60, 52, 44, 36
    , 63, 55, 47, 39, 31, 23, 15
    ,  7, 62, 54, 46, 38, 30, 22
    , 14,  6, 61, 53, 45, 37, 29
    , 21, 13,  5, 28, 20, 12,  4
    ]

-- Permutación PC-2 para generación de subclaves (48 bits de 56)
pc2 :: [Int]
pc2 = 
    [ 14, 17, 11, 24,  1,  5
    ,  3, 28, 15,  6, 21, 10
    , 23, 19, 12,  4, 26,  8
    , 16,  7, 27, 20, 13,  2
    , 41, 52, 31, 37, 47, 55
    , 30, 40, 51, 45, 33, 48
    , 44, 49, 39, 56, 34, 53
    , 46, 42, 50, 36, 29, 32
    ]

-- Número de rotaciones por ronda
shiftSchedule :: [Int]
shiftSchedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

-- Convertir byte a lista de bits
byteToBits :: Word8 -> [Bool]
byteToBits w = [testBit w (7 - i) | i <- [0 .. 7]]

-- Convertir lista de bits a byte
bitsToWord8 :: [Bool] -> Word8
bitsToWord8 bits = foldl setBitAt 0 (zip [7, 6 .. 0] bits)
  where
    setBitAt w (i, True) = setBit w i
    setBitAt w (_, False) = w

-- Aplicar permutación
permute :: [Int] -> [Bool] -> [Bool]
permute table bits = map (\i -> bits !! (i - 1)) table

-- Rotar bits a la izquierda
rotateLeft :: Int -> [Bool] -> [Bool]
rotateLeft n bits = drop n bits ++ take n bits

-- Generar las 16 subclaves
generateSubkeys :: DESKey -> [[Bool]]
generateSubkeys key = subkeys
  where
    key56 = permute pc1 key
    (c0, d0) = splitAt 28 key56

    rounds =
      scanl
        ( \(c, d) shift ->
            (rotateLeft shift c, rotateLeft shift d)
        )
        (c0, d0)
        shiftSchedule

    subkeys = map (\(c, d) -> permute pc2 (c ++ d)) (tail rounds)

-- Función F (corazón de DES)
fFunction :: [Bool] -> [Bool] -> [Bool]
fFunction rightHalf subkey = permute permutationTable afterSBoxes
  where
    expanded = permute expansionTable rightHalf
    xored = zipWith (/=) expanded subkey
    -- Dividir en 8 grupos de 6 bits
    groups = chunksOf 6 xored
    -- Aplicar S-boxes
    afterSBoxes = concatMap applySBox (zip groups sBoxes)
    applySBox :: ([Bool], [[Int]]) -> [Bool]
    applySBox (bits, sBox) =
      let row = boolToInt [bits !! 0, bits !! 5]
          col = boolToInt (take 4 $ drop 1 bits)
          value = sBox !! row !! col
       in intToBits4 value
    boolToInt :: [Bool] -> Int
    boolToInt bs = foldl' (\acc b -> acc * 2 + if b then 1 else 0) 0 bs
    intToBits4 :: Int -> [Bool]
    intToBits4 n = [testBit n (3 - i) | i <- [0 .. 3]]

chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf n xs = take n xs : chunksOf n (drop n xs)

-- Cifrar un bloque de 64 bits
desEncryptBlock :: [[Bool]] -> [Bool] -> [Bool]
desEncryptBlock subkeys block = permute finalPermutation finalBlock
  where
    permuted = permute initialPermutation block
    (l0, r0) = splitAt 32 permuted

    -- 16 rondas
    (lFinal, rFinal) = foldl desRound (l0, r0) subkeys

    -- Intercambio final
    finalBlock = rFinal ++ lFinal

    desRound (left, right) subkey =
      let fResult = fFunction right subkey
          newRight = zipWith (/=) left fResult
       in (right, newRight)

-- Descifrar es lo mismo pero con subclaves en orden inverso
desDecryptBlock :: [[Bool]] -> [Bool] -> [Bool]
desDecryptBlock subkeys = desEncryptBlock (reverse subkeys)

-- Preparar clave de 64 bits desde ByteString
prepareKey :: ByteString -> DESKey
prepareKey bs =
  let keyBytes = BS.take 8 $ bs `BS.append` BS.replicate 8 0
      bits = concatMap byteToBits (BS.unpack keyBytes)
   in take 64 bits

-- Padding PKCS#7
addPadding :: ByteString -> ByteString
addPadding bs =
  let padLen = 8 - (BS.length bs `mod` 8)
      padding = BS.replicate padLen (fromIntegral padLen)
   in bs `BS.append` padding

-- Remover padding
removePadding :: ByteString -> ByteString
removePadding bs =
  if BS.null bs
    then bs
    else
      let lastByte = BS.last bs
          padLen = fromIntegral lastByte
       in if padLen > 0 && padLen <= 8
            then BS.take (BS.length bs - padLen) bs
            else bs

-- Cifrar ByteString completo
desEncrypt :: DESKey -> ByteString -> ByteString
desEncrypt key plaintext =
  let subkeys = generateSubkeys key
      padded = addPadding plaintext
      blocks = chunksOf 8 $ BS.unpack padded
      encryptedBlocks = map (encryptBlock subkeys) blocks
   in BS.pack $ concat encryptedBlocks
  where
    encryptBlock :: [[Bool]] -> [Word8] -> [Word8]
    encryptBlock subkeys bytes =
      let bits = concatMap byteToBits bytes
          encrypted = desEncryptBlock subkeys bits
          encBytes = map bitsToWord8 (chunksOf 8 encrypted)
       in encBytes

-- Descifrar ByteString completo
desDecrypt :: DESKey -> ByteString -> ByteString
desDecrypt key ciphertext =
  let subkeys = generateSubkeys key
      blocks = chunksOf 8 $ BS.unpack ciphertext
      decryptedBlocks = map (decryptBlock subkeys) blocks
      decrypted = BS.pack $ concat decryptedBlocks
   in removePadding decrypted
  where
    decryptBlock :: [[Bool]] -> [Word8] -> [Word8]
    decryptBlock subkeys bytes =
      let bits = concatMap byteToBits bytes
          decrypted = desDecryptBlock subkeys bits
          decBytes = map bitsToWord8 (chunksOf 8 decrypted)
       in decBytes