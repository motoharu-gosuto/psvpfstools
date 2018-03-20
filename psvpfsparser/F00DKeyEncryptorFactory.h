#pragma once

#include <string>
#include <memory>

#include "IF00DKeyEncryptor.h"

std::shared_ptr<IF00DKeyEncryptor> get_F00D_encryptor();

void set_F00D_url(std::string url);