#pragma once
#ifndef SELFLOCK_SL_H
#define SELFLOCK_SL_H

// Dynamically load module with config if it's updated
void reload_config();

int sl_enum_init();

void sl_enum_restrict();

void sl_enum_free();

#endif //SELFLOCK_SL_H
