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
#include <fstream>
#include <iostream>
#include <vector>

// #include <openfhe.h>

using namespace lbcrypto;

const int PLAINTEXT_MODULUS = 65537; // Default plaintext modulus / 2
const size_t MAX_DATA_POINTS = 100;  // Limit to first 100 data points

// Function to read data from a file, convert to integers, and apply modulus
std::vector<int> readDataFromFile(const std::string &filePath) {
  std::vector<int> data;
  std::ifstream file(filePath);
  if (!file.is_open()) {
    throw std::runtime_error("Could not open file: " + filePath);
  }

  double value;
  size_t count = 0;
  while (file >> value && count < MAX_DATA_POINTS) {
    int modValue = static_cast<int>(std::floor(value)) %
                   PLAINTEXT_MODULUS; // Convert to integer and mod
    if (modValue < 0) {
      modValue %= -modValue % PLAINTEXT_MODULUS; // Ensure non-negative values
    }
    data.push_back(modValue);
    count++;
  }
  file.close();

  return data;
}

// Hades Basic: Key Generation
struct HadesBasicKey {
  CryptoContext<DCRTPoly> cryptoContext;
  KeyPair<DCRTPoly> keyPair;
  PrivateKey<DCRTPoly> compareEvalKey; // Compare-Eval Key (CEK) as Ciphertext
};

// TODO: Move the "scale" from secret key to parameters
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

Ciphertext<DCRTPoly> hades_fae_encrypt(const HadesBasicKey &hadesKey,
                                       const int64_t plaintextValue) {
  // Step 1: Create plaintext object
  Plaintext plaintext =
      hadesKey.cryptoContext->MakePackedPlaintext({plaintextValue});

  // Step 2: Sample a scaling factor uniformly from a predefined range
  int scale = rand() % 10 + 1; // Example: scaling factor between 1 and 10

  // Step 3: Sample a perturbation value from a bounded range
  double epsilon = 0.01; // Example: small perturbation factor
  double delta = ((double)rand() / RAND_MAX) * (2 * epsilon) -
                 epsilon; // Range: [-epsilon, epsilon]

  // Step 4: Sample a noise polynomial
  std::vector<int64_t> noiseCoeffs = {rand() % 3, rand() % 3,
                                      rand() % 3}; // Example noise
  Plaintext noisePoly =
      hadesKey.cryptoContext->MakePackedPlaintext(noiseCoeffs);

  // Step 5: Modify the packed values of the plaintext
  auto packedValues =
      plaintext->GetPackedValue(); // Access the packed values (reference)
  for (size_t i = 0; i < packedValues.size(); ++i) {
    packedValues[i] =
        packedValues[i] * scale + static_cast<int64_t>(delta * scale);
    packedValues[i] %= PLAINTEXT_MODULUS; // Make sure it's within MODULUS
  }

  // Add noise polynomial to the modified plaintext
  auto combinedPlaintext =
      hadesKey.cryptoContext->MakePackedPlaintext(packedValues);

  auto combinedCipher = hadesKey.cryptoContext->Encrypt(
      hadesKey.keyPair.publicKey, combinedPlaintext);
  auto noiseCipher =
      hadesKey.cryptoContext->Encrypt(hadesKey.keyPair.publicKey, noisePoly);
  auto resultCipher =
      hadesKey.cryptoContext->EvalAdd(noiseCipher, combinedCipher);

  // Step 6: Encrypt the modified plaintext
  return hadesKey.cryptoContext->Encrypt(hadesKey.keyPair.publicKey,
                                         combinedPlaintext);
}

// TODO: need to multiple ct0 by the "scale" for comparison eval.
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

void test_hades_fae(const std::vector<int> &inputIntegers) {
  using Clock = std::chrono::high_resolution_clock;

  // Step 1: Generate HADES key
  auto hadesKey = hades_basic_keygen();

  // Step 2: Measure encryption time
  std::vector<Ciphertext<DCRTPoly>> encryptedIntegers;
  auto startEncrypt = Clock::now();
  for (const auto &val : inputIntegers) {
    auto ct = hades_fae_encrypt(hadesKey, val);
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
  std::cout << "HADES FA-Extension Test Results:" << std::endl;
  std::cout << "Average Encryption Time: " << avgEncryptTime
            << " microseconds per integer" << std::endl;
  std::cout << "Average Comparison Time: " << avgCompareTime
            << " microseconds per pair" << std::endl;
}

// Test function for HADES Basic
void test_app_basic(const std::string &filePath) {
  try {
    std::vector<int> inputValues = readDataFromFile(filePath);
    using Clock = std::chrono::high_resolution_clock;

    // Step 1: Measure key generation time
    auto startKeygen = Clock::now();
    auto hadesKey = hades_basic_keygen();
    auto endKeygen = Clock::now();
    auto keygenTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                          endKeygen - startKeygen)
                          .count();

    // Step 2: Measure encryption time
    std::vector<Ciphertext<DCRTPoly>> encryptedValues;
    auto startEncrypt = Clock::now();
    for (const auto &val : inputValues) {
      auto ct = hades_basic_encrypt(hadesKey, val);
      encryptedValues.push_back(ct);
    }
    auto endEncrypt = Clock::now();
    auto encryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                           endEncrypt - startEncrypt)
                           .count();

    // Step 3: Measure pair-wise comparison time
    auto startCompare = Clock::now();
    for (size_t i = 0; i < encryptedValues.size(); ++i) {
      for (size_t j = i + 1; j < encryptedValues.size(); ++j) {
        int result = hades_basic_compare(hadesKey, encryptedValues[i],
                                         encryptedValues[j]);
        (void)result; // Ignore the result in this benchmark
      }
    }
    auto endCompare = Clock::now();
    auto compareTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                           endCompare - startCompare)
                           .count();

    // Output results
    std::cout << "HADES BFV Basic Test Results for file: " << filePath
              << std::endl;
    std::cout << "Total Key Generation Time: " << keygenTime << " ms"
              << std::endl;
    std::cout << "Total Encryption Time: " << encryptTime << " ms" << std::endl;
    std::cout << "Total Comparison Time: " << compareTime << " ms" << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
  }
}

// Test function for HADES FA-Extension
void test_app_fae(const std::string &filePath) {
  try {
    std::vector<int> inputValues = readDataFromFile(filePath);
    using Clock = std::chrono::high_resolution_clock;

    // Step 1: Generate HADES key
    auto hadesKey = hades_basic_keygen();

    // Step 2: Measure encryption time
    std::vector<Ciphertext<DCRTPoly>> encryptedValues;
    auto startEncrypt = Clock::now();
    for (const auto &val : inputValues) {
      auto ct = hades_fae_encrypt(hadesKey, val);
      encryptedValues.push_back(ct);
    }
    auto endEncrypt = Clock::now();
    auto encryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                           endEncrypt - startEncrypt)
                           .count();

    // Step 3: Measure pair-wise comparison time
    auto startCompare = Clock::now();
    for (size_t i = 0; i < encryptedValues.size(); ++i) {
      for (size_t j = i + 1; j < encryptedValues.size(); ++j) {
        int result = hades_basic_compare(hadesKey, encryptedValues[i],
                                         encryptedValues[j]);
        (void)result; // Ignore the result in this benchmark
      }
    }
    auto endCompare = Clock::now();
    auto compareTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                           endCompare - startCompare)
                           .count();

    // Output results
    std::cout << "HADES BFV FA-Extension Test Results for file: " << filePath
              << std::endl;
    std::cout << "Total Encryption Time: " << encryptTime << " ms" << std::endl;
    std::cout << "Total Comparison Time: " << compareTime << " ms" << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
  }
}

int main() {
  std::cout << std::endl;
  std::cout << "======================= " << std::endl;
  std::cout << "===== HPDIC Hades ===== " << std::endl;
  std::cout << "======================= " << std::endl;
  std::cout << std::endl;

  std::vector<int> test_vec = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  test_hades_basic(test_vec);
  test_hades_fae(test_vec);

  const std::string basePath = "../data/";
  const std::vector<std::string> datasets = {"bitcoin", "covid19", "hg38"};

  std::cout << "Select a dataset to test:\n";
  for (size_t i = 0; i < datasets.size(); ++i) {
    std::cout << i + 1 << ": " << datasets[i] << std::endl;
  }
  std::cout << "0: Exit" << std::endl;

  int choice;
  std::cin >> choice;

  if (choice == 0) {
    std::cout << "Exiting program." << std::endl;
    return 0;
  }

  if (choice < 1 || choice > static_cast<int>(datasets.size())) {
    std::cerr << "Invalid choice. Exiting." << std::endl;
    return 1;
  }

  std::string filePath = basePath + datasets[choice - 1];

  // Run tests on the selected dataset
  test_app_basic(filePath);
  test_app_fae(filePath);

  return 0;
}
