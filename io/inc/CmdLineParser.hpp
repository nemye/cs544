#pragma once

#include <algorithm>
#include <string>
#include <vector>

class CmdLineParser {
 protected:
  using String = std::string;

 public:
  CmdLineParser(const int& arc, const char**& argv);
  String get(const String& opt_short, const String& opt_long);
  bool exists(const String& opt_short, const String& opt_long);

 private:
  std::vector<String> _options = {};
};