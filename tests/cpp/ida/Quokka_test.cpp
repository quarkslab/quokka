//
// Created by alexis on 07/05/2020.
//

#include "gtest/gtest.h"

#include <iostream>

#include "quokka/Logger.h"

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  quokka::Logger::GetInstance();

  return RUN_ALL_TESTS();
}