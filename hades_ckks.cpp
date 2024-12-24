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

Example for CKKS bootstrapping with full packing

*/

#define PROFILE

#include "openfhe.h"
#include <chrono>
#include <iostream>
#include <vector>

using namespace lbcrypto;

struct HadesBasicKey {
  CryptoContext<DCRTPoly> cryptoContext;
  KeyPair<DCRTPoly> keyPair;
  PrivateKey<DCRTPoly> compareEvalKey; // Compare-Eval Key (CEK)
};

HadesBasicKey hades_basic_keygen() {
  CCParams<CryptoContextCKKSRNS> parameters;

  parameters.SetSecretKeyDist(
      UNIFORM_TERNARY); // Use uniform ternary distribution
  parameters.SetSecurityLevel(HEStd_128_classic); // Standard security level
  parameters.SetRingDim(32768);                   // Set ring dimension
  parameters.SetScalingModSize(59);               // Set scaling modulus
  parameters.SetScalingTechnique(FIXEDAUTO);      // Scaling technique
  parameters.SetFirstModSize(60);
  parameters.SetMultiplicativeDepth(6);

  CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);

  // Generate key pair
  KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

  // Generate CEK (Compare-Eval Key)
  auto secretKeyPoly = keyPair.secretKey->GetPrivateElement();
  int scale = rand() % 10 + 1;
  auto scaledSecretKeyPoly = secretKeyPoly * scale;

  PrivateKey<DCRTPoly> compareEvalKey =
      std::make_shared<PrivateKeyImpl<DCRTPoly>>(
          keyPair.secretKey->GetCryptoContext());
  compareEvalKey->SetPrivateElement(scaledSecretKeyPoly);

  return {cryptoContext, keyPair, compareEvalKey};
}

Ciphertext<DCRTPoly> hades_basic_encrypt(const HadesBasicKey &hadesKey,
                                         const double plaintextValue) {
  // Create plaintext object
  Plaintext plaintext = hadesKey.cryptoContext->MakeCKKSPackedPlaintext(
      {std::complex<double>(plaintextValue, 0.0)}, // Wrap as a complex number
      20,                                           // Scale degree
      0,                                           // Level
      nullptr,                                     // Parameters
      hadesKey.cryptoContext->GetRingDimension() / 2); // Number of slots

  // Encrypt plaintext to generate ciphertext
  return hadesKey.cryptoContext->Encrypt(hadesKey.keyPair.publicKey, plaintext);
}

Ciphertext<DCRTPoly> hades_fae_encrypt(const HadesBasicKey &hadesKey,
                                       const double plaintextValue) {
  // Step 1: Create plaintext object
  Plaintext plaintext = hadesKey.cryptoContext->MakeCKKSPackedPlaintext(
      {std::complex<double>(plaintextValue, 0.0)}, // Wrap as a complex number
      20,                                           // Scale degree
      0,                                           // Level
      nullptr,                                     // Parameters
      hadesKey.cryptoContext->GetRingDimension() / 2); // Number of slots

  // Step 2: Sample a scaling factor uniformly from a predefined range
  double scale = static_cast<double>(rand() % 10 + 1);

  // Step 3: Add perturbation to plaintext value
  double epsilon = 0.01;
  double delta = ((double)rand() / RAND_MAX) * (2 * epsilon) - epsilon;
  double perturbedValue = plaintextValue * scale + delta * scale;

  // Step 4: Encrypt the perturbed value
  Plaintext perturbedPlaintext =
      hadesKey.cryptoContext->MakeCKKSPackedPlaintext(
          {std::complex<double>(perturbedValue,
                                0.0)}, // Wrap as a complex number
          20,                           // Scale degree
          0,                           // Level
          nullptr,                     // Parameters
          hadesKey.cryptoContext->GetRingDimension() / 2);
  return hadesKey.cryptoContext->Encrypt(hadesKey.keyPair.publicKey,
                                         perturbedPlaintext);
}

int hades_basic_compare(const HadesBasicKey &hadesKey,
                        const Ciphertext<DCRTPoly> &ctA,
                        const Ciphertext<DCRTPoly> &ctB) {
  // Subtract ciphertexts to compute the difference
  auto ctDelta = hadesKey.cryptoContext->EvalSub(ctA, ctB);

  // Decrypt the result using CEK
  Plaintext decryptedDelta;
  hadesKey.cryptoContext->Decrypt(hadesKey.compareEvalKey, ctDelta,
                                  &decryptedDelta);

  // Extract the first value from the decrypted plaintext
  auto deltaValue = decryptedDelta->GetCKKSPackedValue()[0];

  // Interpret the result: 1 (A > B), 0 (A == B), -1 (A < B)
  if (deltaValue.real() > 0) {
    return 1;
  } else if (std::abs(deltaValue) < 1e-6) { // Consider small values as zero
    return 0;
  } else {
    return -1;
  }
}

void test_hades_basic(const std::vector<double> &inputValues) {
  using Clock = std::chrono::high_resolution_clock;

  // Step 1: Measure key generation time
  auto startKeygen = Clock::now();
  auto hadesKey = hades_basic_keygen();
  auto endKeygen = Clock::now();
  auto keygenTime = std::chrono::duration_cast<std::chrono::microseconds>(
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
  auto encryptTime = std::chrono::duration_cast<std::chrono::microseconds>(
                         endEncrypt - startEncrypt)
                         .count();
  double avgEncryptTime = static_cast<double>(encryptTime) / inputValues.size();

  // Step 3: Measure comparison time
  auto startCompare = Clock::now();
  for (size_t i = 0; i < encryptedValues.size(); ++i) {
    for (size_t j = i + 1; j < encryptedValues.size(); ++j) {
      int result =
          hades_basic_compare(hadesKey, encryptedValues[i], encryptedValues[j]);
      (void)result; // Ignore result for benchmarking
    }
  }
  auto endCompare = Clock::now();
  auto compareTime = std::chrono::duration_cast<std::chrono::microseconds>(
                         endCompare - startCompare)
                         .count();
  double avgCompareTime = static_cast<double>(compareTime) /
                          ((inputValues.size() * (inputValues.size() - 1)) / 2);

  // Output results
  std::cout << "HADES CKKS Basic Test Results:" << std::endl;
  std::cout << "Key Generation Time: " << keygenTime << " microseconds"
            << std::endl;
  std::cout << "Average Encryption Time: " << avgEncryptTime
            << " microseconds per value" << std::endl;
  std::cout << "Average Comparison Time: " << avgCompareTime
            << " microseconds per pair" << std::endl;
}

void test_hades_fae(const std::vector<double> &inputValues) {
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
  auto encryptTime = std::chrono::duration_cast<std::chrono::microseconds>(
                         endEncrypt - startEncrypt)
                         .count();
  double avgEncryptTime = static_cast<double>(encryptTime) / inputValues.size();

  // Step 3: Measure pair-wise comparison time
  auto startCompare = Clock::now();
  for (size_t i = 0; i < encryptedValues.size(); ++i) {
    for (size_t j = i + 1; j < encryptedValues.size(); ++j) {
      int result =
          hades_basic_compare(hadesKey, encryptedValues[i], encryptedValues[j]);
      (void)result; // Ignore the result in this benchmark
    }
  }
  auto endCompare = Clock::now();
  auto compareTime = std::chrono::duration_cast<std::chrono::microseconds>(
                         endCompare - startCompare)
                         .count();
  size_t totalPairs = (inputValues.size() * (inputValues.size() - 1)) / 2;
  double avgCompareTime = static_cast<double>(compareTime) / totalPairs;

  // Output results
  std::cout << "HADES CKKS FA-Extension Test Results:" << std::endl;
  std::cout << "Average Encryption Time: " << avgEncryptTime
            << " microseconds per value" << std::endl;
  std::cout << "Average Comparison Time: " << avgCompareTime
            << " microseconds per pair" << std::endl;
}

void SimpleBootstrapExample();

int main(int argc, char *argv[]) { 
  
  SimpleBootstrapExample();

  std::cout << std::endl;
  std::cout << "======================= " << std::endl;
  std::cout << "===== HPDIC Hades ===== " << std::endl;
  std::cout << "======================= " << std::endl;
  std::cout << std::endl;

  std::vector<double> test_vec = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  test_hades_basic(test_vec);
  test_hades_fae(test_vec);
}

void SimpleBootstrapExample() {
  CCParams<CryptoContextCKKSRNS> parameters;
  // A. Specify main parameters
  /*  A1) Secret key distribution
   * The secret key distribution for CKKS should either be SPARSE_TERNARY or
   * UNIFORM_TERNARY. The SPARSE_TERNARY distribution was used in the original
   * CKKS paper, but in this example, we use UNIFORM_TERNARY because this is
   * included in the homomorphic encryption standard.
   */
  SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
  parameters.SetSecretKeyDist(secretKeyDist);

  /*  A2) Desired security level based on FHE standards.
   * In this example, we use the "NotSet" option, so the example can run more
   * quickly with a smaller ring dimension. Note that this should be used only
   * in non-production environments, or by experts who understand the security
   * implications of their choices. In production-like environments, we
   * recommend using HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic
   * for 128-bit, 192-bit, or 256-bit security, respectively. If you choose one
   * of these as your security level, you do not need to set the ring dimension.
   */
  parameters.SetSecurityLevel(HEStd_NotSet);
  parameters.SetRingDim(1 << 12);

  /*  A3) Scaling parameters.
   * By default, we set the modulus sizes and rescaling technique to the
   * following values to obtain a good precision and performance tradeoff. We
   * recommend keeping the parameters below unless you are an FHE expert.
   */
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
  ScalingTechnique rescaleTech = FIXEDAUTO;
  usint dcrtBits = 78;
  usint firstMod = 89;
#else
  ScalingTechnique rescaleTech = FLEXIBLEAUTO;
  usint dcrtBits = 59;
  usint firstMod = 60;
#endif

  parameters.SetScalingModSize(dcrtBits);
  parameters.SetScalingTechnique(rescaleTech);
  parameters.SetFirstModSize(firstMod);

  /*  A4) Multiplicative depth.
   * The goal of bootstrapping is to increase the number of available levels we
   * have, or in other words, to dynamically increase the multiplicative depth.
   * However, the bootstrapping procedure itself needs to consume a few levels
   * to run. We compute the number of bootstrapping levels required using
   * GetBootstrapDepth, and add it to levelsAvailableAfterBootstrap to set our
   * initial multiplicative depth. We recommend using the input parameters below
   * to get started.
   */
  std::vector<uint32_t> levelBudget = {4, 4};

  // Note that the actual number of levels avalailable after bootstrapping
  // before next bootstrapping will be levelsAvailableAfterBootstrap - 1 because
  // an additional level is used for scaling the ciphertext before next
  // bootstrapping (in 64-bit CKKS bootstrapping)
  uint32_t levelsAvailableAfterBootstrap = 10;
  usint depth = levelsAvailableAfterBootstrap +
                FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
  parameters.SetMultiplicativeDepth(depth);

  CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);
  cryptoContext->Enable(ADVANCEDSHE);
  cryptoContext->Enable(FHE);

  usint ringDim = cryptoContext->GetRingDimension();
  // This is the maximum number of slots that can be used for full packing.
  usint numSlots = ringDim / 2;
  std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl
            << std::endl;

  cryptoContext->EvalBootstrapSetup(levelBudget);

  auto keyPair = cryptoContext->KeyGen();
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);
  cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

  std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
  size_t encodedLength = x.size();

  // We start with a depleted ciphertext that has used up all of its levels.
  Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1);

  ptxt->SetLength(encodedLength);
  std::cout << "Input: " << ptxt << std::endl;

  Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

  std::cout << "Initial number of levels remaining: "
            << depth - ciph->GetLevel() << std::endl;

  // Perform the bootstrapping operation. The goal is to increase the number of
  // levels remaining for HE computation.
  auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);

  std::cout << "Number of levels remaining after bootstrapping: "
            << depth - ciphertextAfter->GetLevel() -
                   (ciphertextAfter->GetNoiseScaleDeg() - 1)
            << std::endl
            << std::endl;

  Plaintext result;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
  result->SetLength(encodedLength);
  std::cout << "Output after bootstrapping \n\t" << result << std::endl;
}
