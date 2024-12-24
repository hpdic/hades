//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other
// contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  HPDIC: Basic Hades
 */

#include "openfhe.h"
#include <chrono>
#include <iostream>
#include <vector>
// #include <openfhe.h>

using namespace lbcrypto;

// Hades Basic: Key Generation
struct HadesBasicKey {
  CryptoContext<DCRTPoly> cryptoContext;
  KeyPair<DCRTPoly> keyPair;
  PrivateKey<DCRTPoly> compareEvalKey; // Compare-Eval Key (CEK) as Ciphertext
};

HadesBasicKey hades_basic_keygen() {
  // Set up BFV parameters
  CCParams<CryptoContextBFVRNS> parameters;
  parameters.SetPlaintextModulus(
      65537); // A large prime number for plaintext modulus
  parameters.SetMultiplicativeDepth(2); // Adjust depth as needed

  CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);

  // Generate key pair
  KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

  // Extract the private key polynomial
  auto secretKeyPoly = keyPair.secretKey->GetPrivateElement();

  // Scale the private key
  int scale = rand() % 10 + 1; // Random scale factor between 1 and 10
  auto scaledSecretKeyPoly = secretKeyPoly * scale;

  // Add random noise to the scaled private key
  std::vector<int64_t> randomNoise = {rand() % 3, rand() % 3, rand() % 3};
  for (size_t i = 0; i < randomNoise.size(); ++i) {
    auto noisePoly =
        scaledSecretKeyPoly.GetElementAtIndex(0); // 获取 CRT 多项式
    noisePoly[i].ModAddEq(randomNoise[i],
                          noisePoly.GetModulus());       // 模加随机噪声
    scaledSecretKeyPoly.SetElementAtIndex(0, noisePoly); // 更新 CRT 元素
  }
  // DFZ: OpenFHE doesn't support index operator:
//   for (size_t i = 0; i < randomNoise.size(); ++i) {
//     scaledSecretKeyPoly[i] += randomNoise[i];
//   }

  // Wrap the modified private key back into a PrivateKey structure
  PrivateKey<DCRTPoly> compareEvalKey =
      std::make_shared<PrivateKeyImpl<DCRTPoly>>(
          keyPair.secretKey->GetCryptoContext());
  compareEvalKey->SetPrivateElement(scaledSecretKeyPoly);

  return {cryptoContext, keyPair, compareEvalKey};
}

// Hades Basic: Encryption
Ciphertext<DCRTPoly> hades_basic_encrypt(const HadesBasicKey &hadesKey,
                                         const int64_t plaintextValue) {
  // Create plaintext object
  Plaintext plaintext =
      hadesKey.cryptoContext->MakePackedPlaintext({plaintextValue});

  // Encrypt plaintext to generate ciphertext
  return hadesKey.cryptoContext->Encrypt(hadesKey.keyPair.publicKey, plaintext);
}

// Hades Basic: Comparison
int hades_basic_compare(const HadesBasicKey &hadesKey,
                        const Ciphertext<DCRTPoly> &ctA,
                        const Ciphertext<DCRTPoly> &ctB) {
  // Subtract ciphertexts to compute the difference (ctA - ctB)
  auto ctDelta = hadesKey.cryptoContext->EvalSub(ctA, ctB);

  // Decrypt the result using CEK
  Plaintext decryptedDelta;
  hadesKey.cryptoContext->Decrypt(hadesKey.compareEvalKey, ctDelta,
                                  &decryptedDelta);

  // Ensure the plaintext has the correct length
  decryptedDelta->SetLength(1);

  // Extract the scalar value from the decrypted result
  int64_t deltaValue = decryptedDelta->GetPackedValue()[0];

  // Interpret the result: 1 (A > B), 0 (A == B), -1 (A < B)
  if (deltaValue > 0) {
    return 1;
  } else if (deltaValue == 0) {
    return 0;
  } else {
    return -1;
  }
}

// Function to test HADES Basic
void test_hades_basic(const std::vector<int> &inputIntegers) {
  using Clock = std::chrono::high_resolution_clock;

  // Step 1: Measure key generation time
  auto startKeygen = Clock::now();
  auto hadesKey = hades_basic_keygen();
  auto endKeygen = Clock::now();
  auto keygenTime = std::chrono::duration_cast<std::chrono::microseconds>(
                        endKeygen - startKeygen)
                        .count();

  // Step 2: Measure encryption time
  std::vector<Ciphertext<DCRTPoly>> encryptedIntegers;
  auto startEncrypt = Clock::now();
  for (const auto &val : inputIntegers) {
    auto ct = hades_basic_encrypt(hadesKey, val);
    encryptedIntegers.push_back(ct);
  }
  auto endEncrypt = Clock::now();
  auto encryptTime = std::chrono::duration_cast<std::chrono::microseconds>(
                         endEncrypt - startEncrypt)
                         .count();
  double avgEncryptTime =
      static_cast<double>(encryptTime) / inputIntegers.size();

  // Step 3: Measure pair-wise comparison time
  auto startCompare = Clock::now();
  for (size_t i = 0; i < encryptedIntegers.size(); ++i) {
    for (size_t j = i + 1; j < encryptedIntegers.size(); ++j) {
      int result = hades_basic_compare(hadesKey, encryptedIntegers[i],
                                       encryptedIntegers[j]);
      (void)result; // Ignore the result in this benchmark
    }
  }
  auto endCompare = Clock::now();
  auto compareTime = std::chrono::duration_cast<std::chrono::microseconds>(
                         endCompare - startCompare)
                         .count();
  size_t totalPairs = (inputIntegers.size() * (inputIntegers.size() - 1)) / 2;
  double avgCompareTime = static_cast<double>(compareTime) / totalPairs;

  // Output results
  std::cout << "HADES Basic Test Results:" << std::endl;
  std::cout << "Key Generation Time: " << keygenTime << " microseconds"
            << std::endl;
  std::cout << "Average Encryption Time: " << avgEncryptTime
            << " microseconds per integer" << std::endl;
  std::cout << "Average Comparison Time: " << avgCompareTime
            << " microseconds per pair" << std::endl;
}

int main() {
  // Sample Program: Step 1: Set CryptoContext
  CCParams<CryptoContextBFVRNS> parameters;
  parameters.SetPlaintextModulus(65537);
  parameters.SetMultiplicativeDepth(2);

  CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
  // Enable features that you wish to use
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);

  // Sample Program: Step 2: Key Generation

  // Initialize Public Key Containers
  KeyPair<DCRTPoly> keyPair;

  // Generate a public/private key pair
  keyPair = cryptoContext->KeyGen();

  // Generate the relinearization key
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  // Generate the rotation evaluation keys
  cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

  // Sample Program: Step 3: Encryption

  // First plaintext vector is encoded
  std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
  // Second plaintext vector is encoded
  std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);
  // Third plaintext vector is encoded
  std::vector<int64_t> vectorOfInts3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12};
  Plaintext plaintext3 = cryptoContext->MakePackedPlaintext(vectorOfInts3);

  // The encoded vectors are encrypted
  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
  auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);

  // Sample Program: Step 4: Evaluation

  // Homomorphic additions
  auto ciphertextAdd12 = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
  auto ciphertextAddResult =
      cryptoContext->EvalAdd(ciphertextAdd12, ciphertext3);

  // Homomorphic multiplications
  auto ciphertextMul12 = cryptoContext->EvalMult(ciphertext1, ciphertext2);
  auto ciphertextMultResult =
      cryptoContext->EvalMult(ciphertextMul12, ciphertext3);

  // Homomorphic rotations
  auto ciphertextRot1 = cryptoContext->EvalRotate(ciphertext1, 1);
  auto ciphertextRot2 = cryptoContext->EvalRotate(ciphertext1, 2);
  auto ciphertextRot3 = cryptoContext->EvalRotate(ciphertext1, -1);
  auto ciphertextRot4 = cryptoContext->EvalRotate(ciphertext1, -2);

  // Sample Program: Step 5: Decryption

  // Decrypt the result of additions
  Plaintext plaintextAddResult;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult,
                         &plaintextAddResult);

  // Decrypt the result of multiplications
  Plaintext plaintextMultResult;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResult,
                         &plaintextMultResult);

  // Decrypt the result of rotations
  Plaintext plaintextRot1;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot1, &plaintextRot1);
  Plaintext plaintextRot2;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot2, &plaintextRot2);
  Plaintext plaintextRot3;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot3, &plaintextRot3);
  Plaintext plaintextRot4;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot4, &plaintextRot4);

  plaintextRot1->SetLength(vectorOfInts1.size());
  plaintextRot2->SetLength(vectorOfInts1.size());
  plaintextRot3->SetLength(vectorOfInts1.size());
  plaintextRot4->SetLength(vectorOfInts1.size());

  std::cout << "Plaintext #1: " << plaintext1 << std::endl;
  std::cout << "Plaintext #2: " << plaintext2 << std::endl;
  std::cout << "Plaintext #3: " << plaintext3 << std::endl;

  // Output results
  std::cout << "\nResults of homomorphic computations" << std::endl;
  std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
  std::cout << "#1 * #2 * #3: " << plaintextMultResult << std::endl;
  std::cout << "Left rotation of #1 by 1: " << plaintextRot1 << std::endl;
  std::cout << "Left rotation of #1 by 2: " << plaintextRot2 << std::endl;
  std::cout << "Right rotation of #1 by 1: " << plaintextRot3 << std::endl;
  std::cout << "Right rotation of #1 by 2: " << plaintextRot4 << std::endl;

  std::cout << std::endl;
  std::cout << "======================= " << std::endl;
  std::cout << "===== HPDIC Hades ===== " << std::endl;
  std::cout << "======================= " << std::endl;
  std::cout << std::endl;

  std::vector<int> test_vec = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  test_hades_basic(test_vec);

  return 0;
}
